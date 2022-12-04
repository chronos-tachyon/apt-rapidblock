#!/usr/bin/env python3
"""A script to automatically generate Debian packages for RapidBlock releases."""

import datetime
import json
import os
import os.path
import re
import shutil
import subprocess
import typing
import types

from pathlib import Path
from subprocess import PIPE

import github
import tzlocal
import urllib3

RE_ASSET = re.compile(
        r'^'
        r'(?P<base>rapidblock)'
        r'-'
        r'(?P<os>linux)'
        r'-'
        r'(?P<arch>(?:amd64|arm64))'
        r'(?P<ext>(?:\.exe|\.intoto\.jsonl)?)'
        r'$')
RE_TAG = re.compile(
        r'^'
        r'v'
        r'(?P<major>0|[1-9][0-9]*)'
        r'\.'
        r'(?P<minor>0|[1-9][0-9]*)'
        r'\.'
        r'(?P<patch>0|[1-9][0-9]*)'
        r'(?:'
        r'-'
        r'(?P<prerelease>'
        r'(?:0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)'
        r'(?:\.(?:0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*))*'
        r')'
        r')?'
        r'$')
RE_VCS_REVISION = re.compile(r'^\tbuild\tvcs\.revision=([0-9a-f]{40})$')

ASCII = 'ascii'
UTF8 = 'utf-8'

ROOT_DIR = Path.cwd()
TEMPLATE_DIR = ROOT_DIR / 'template'
TEMPLATE_CONTROL = TEMPLATE_DIR / 'control'
TEMPLATE_DISTRIBUTIONS = TEMPLATE_DIR / 'distributions'
TEMPLATE_OPTIONS = TEMPLATE_DIR / 'options'
DOWNLOAD_DIR = ROOT_DIR / 'download'
BUILD_DIR = ROOT_DIR / 'build'
REPREPRO_DIR = ROOT_DIR / 'reprepro'
REPREPRO_CONF = REPREPRO_DIR / 'conf'
REPREPRO_CONF_DISTRIBUTIONS = REPREPRO_CONF / 'distributions'
REPREPRO_CONF_OPTIONS = REPREPRO_CONF / 'options'
REPREPRO_INCOMING = REPREPRO_DIR / 'incoming'
OUT_DIR = ROOT_DIR / 'out'
OUT_GPGKEY_ASC = OUT_DIR / 'keys.asc'
OUT_GPGKEY_GPG = OUT_DIR / 'keys.gpg'
PUBLISH_SCRIPT = ROOT_DIR / 'publish.sh'
DISTRIBUTION = 'rapidblock'
COMPONENT = 'main'

GNUPG_HOME = Path(os.path.expanduser('~/secure/reprepro-gpg-home'))
GNUPG_KEY = 'FAC9D418F6E454B22FC7ECE0E64E273DA571F3DB'

GITHUB_TOKEN_PATH = Path(os.path.expanduser('~/secure/github-apt-token.pw'))
GITHUB_TOKEN = GITHUB_TOKEN_PATH.read_text(encoding=UTF8).strip()
GITHUB_USER = 'chronos-tachyon'
GITHUB_REPO = 'rapidblock'

TZ = tzlocal.get_localzone()
EPOCH = 1640995200
POOL_MANAGER = urllib3.PoolManager()

AssetType = typing.Literal['unknown', 'sourceTar', 'sourceZip', 'executable', 'provenance']
ASSET_TYPE_UNKNOWN: AssetType = 'unknown'
ASSET_TYPE_SOURCE_TAR: AssetType = 'sourceTar'
ASSET_TYPE_SOURCE_ZIP: AssetType = 'sourceZip'
ASSET_TYPE_EXECUTABLE: AssetType = 'executable'
ASSET_TYPE_PROVENANCE: AssetType = 'provenance'

OSName = typing.Literal['linux']
OS_NAME_LINUX: OSName = 'linux'

ArchName = typing.Literal['amd64', 'arm64']
ARCH_NAME_AMD64: ArchName = 'amd64'
ARCH_NAME_ARM64: ArchName = 'arm64'

ChecksumName = typing.Literal['md5', 'sha1', 'sha256']
CHECKSUM_NAME_MD5: ChecksumName = 'md5'
CHECKSUM_NAME_SHA1: ChecksumName = 'sha1'
CHECKSUM_NAME_SHA256: ChecksumName = 'sha256'

LogLevel = typing.Literal['INFO', 'WARN', 'ERROR']
LOG_LEVEL_INFO: LogLevel = 'INFO'
LOG_LEVEL_WARN: LogLevel = 'WARN'
LOG_LEVEL_ERROR: LogLevel = 'ERROR'


class VersionDict(typing.TypedDict):
    """\
    This pseudoclass marks a dict holding the version information for a GitHub release.

    It is not a real class; it only exists during type checking and is
    discarded at runtime.
    """
    full: str
    major: int
    minor: int
    patch: int
    prerelease: typing.Optional[str]
    build: typing.Optional[str]


def parse_version_dict(tag: str) -> typing.Optional[VersionDict]:
    """\
    This function parses a GitHub release tag as a VersionDict.
    """

    match_result = RE_TAG.match(tag)
    if not match_result:
        return None

    major = int(match_result.group('major'))
    minor = int(match_result.group('minor'))
    patch = int(match_result.group('patch'))
    prerelease: typing.Optional[str] = match_result.group('prerelease')
    if not prerelease:
        prerelease = None

    full = f'{major}.{minor}.{patch}'
    if prerelease:
        full += f'-{prerelease}'

    return {
        'full': full,
        'major': major,
        'minor': minor,
        'patch': patch,
        'prerelease': prerelease,
        'build': None,
    }


def update_version_dict_build(
    version: VersionDict,
    build: typing.Optional[str],
) -> None:
    """\
    This function updates a VersionDict with a new build ID string.
    """

    if not build:
        build = None

    major = version['major']
    minor = version['minor']
    patch = version['patch']
    prerelease = version['prerelease']

    full = f'{major}.{minor}.{patch}'
    if prerelease:
        full += f'-{prerelease}'
    if build:
        full += f'+{build}'

    version['build'] = build
    version['full'] = full


class AssetDict(typing.TypedDict, total=False):
    """\
    This pseudoclass marks a dict holding data for a GitHub release asset.

    It is not a real class; it only exists during type checking and is
    discarded at runtime.
    """
    url: str
    name: str
    type: AssetType
    # The following fields are optional:
    base: str
    ext: str
    os: OSName
    arch: ArchName


# pylint: disable-msg=redefined-builtin
def make_asset_dict(
    url: str,
    name: str,
    /, *,
    type: typing.Optional[AssetType] = None,
) -> AssetDict:
    """\
    This function parses the filename of a release asset as an AssetDict.
    """

    result: AssetDict = {
        'url': url,
        'name': name,
        'type': type if type else ASSET_TYPE_UNKNOWN,
    }

    match_result = RE_ASSET.match(name)
    if match_result:
        result['base'] = match_result.group('base')
        result['ext'] = match_result.group('ext')
        result['os'] = typing.cast(OSName, match_result.group('os'))
        result['arch'] = typing.cast(ArchName, match_result.group('arch'))
        if type is None:
            if result['ext'] == '.intoto.jsonl':
                result['type'] = ASSET_TYPE_PROVENANCE
            elif result['ext'] in ('', '.exe'):
                result['type'] = ASSET_TYPE_EXECUTABLE

    return result


def extract_build_id(path: Path) -> typing.Optional[str]:
    """\
    This function uses the 'go version' command to extract the build ID from
    a compiled Go executable.

    The OS / CPU architecture of the executable does not need to match the OS /
    CPU architecture of the host running the script.
    """
    cmd: list[str] = ['go', 'version', '-m', os.fspath(path)]
    process = subprocess.run(cmd, check=True, capture_output=True)
    for line in process.stdout.decode(UTF8).split('\n'):
        line = line.rstrip()
        match_result = RE_VCS_REVISION.match(line)
        if match_result:
            return match_result.group(1)
    return None


class ReleaseDict(typing.TypedDict):
    """\
    This pseudoclass marks a dict holding data for a GitHub release.

    It is not a real class; it only exists during type checking and is
    discarded at runtime.
    """
    tag: str
    title: str
    body: str
    version: VersionDict
    assets: list[AssetDict]


# pylint: disable-msg=too-many-instance-attributes
class BuildTree:
    """\
    This class represents the temporary filesystem tree within which we are
    trying to build a Debian package.
    """

    root: Path

    src_root: Path
    src_dist: Path
    src_dist_debian_control: Path
    src_dist_debian_conffiles: Path
    src_dist_cron_sh: Path
    src_dist_cron_tab: Path
    src_dist_cron_default: Path
    src_dist_pubkey: Path

    out_root: Path
    out_opt: Path
    out_app: Path
    out_app_bin: Path
    out_app_bin_executable: Path
    out_app_scripts: Path
    out_app_scripts_cron: Path
    out_app_share: Path
    out_app_share_pubkey: Path
    out_app_share_provenance: Path
    out_etc: Path
    out_etc_crond: Path
    out_etc_crond_crontab: Path
    out_etc_default: Path
    out_etc_default_rapidblock: Path

    debian_root: Path
    debian_control: Path
    debian_conffiles: Path
    debian_md5sums: Path
    debian_sha1sums: Path
    debian_sha256sums: Path

    def __init__(self: 'BuildTree', root: Path) -> None:
        """Constructor."""

        self.root = root

        self.src_root = self.root / 'src'
        self.src_dist = self.src_root / 'dist'
        self.src_dist_debian_control = self.src_dist / 'debian.control'
        self.src_dist_debian_conffiles = self.src_dist / 'debian.conffiles'
        self.src_dist_cron_sh = self.src_dist / 'cron.sh'
        self.src_dist_cron_tab = self.src_dist / 'cron.crontab'
        self.src_dist_cron_default = self.src_dist / 'cron.default'
        self.src_dist_pubkey = self.src_dist / 'rapidblock_dot_org.pub'

        self.out_root = self.root / 'out'
        self.out_opt = self.out_root / 'opt'
        self.out_app = self.out_opt / 'rapidblock'
        self.out_app_bin = self.out_app / 'bin'
        self.out_app_bin_executable = self.out_app_bin / 'rapidblock'
        self.out_app_scripts = self.out_app / 'scripts'
        self.out_app_scripts_cron = self.out_app_scripts / 'cron.sh'
        self.out_app_share = self.out_app / 'share'
        self.out_app_share_pubkey = self.out_app_share / 'rapidblock-dot-org.pub'
        self.out_app_share_provenance = self.out_app_share / 'rapidblock.intoto.jsonl'
        self.out_etc = self.out_root / 'etc'
        self.out_etc_crond = self.out_etc / 'cron.d'
        self.out_etc_crond_crontab = self.out_etc_crond / 'rapidblock'
        self.out_etc_default = self.out_etc / 'default'
        self.out_etc_default_rapidblock = self.out_etc_default / 'rapidblock'

        self.debian_root = self.out_root / 'DEBIAN'
        self.debian_control = self.debian_root / 'control'
        self.debian_conffiles = self.debian_root / 'conffiles'
        self.debian_md5sums = self.debian_root / 'md5sums'
        self.debian_sha1sums = self.debian_root / 'sha1sums'
        self.debian_sha256sums = self.debian_root / 'sha256sums'

    def __enter__(self: 'BuildTree') -> 'BuildTree':
        """Context manager entrypoint."""
        if self.root.exists():
            self.remove()
        self.create()
        return self

    def __exit__(
        self: 'BuildTree',
        exc_type: typing.Optional[type[BaseException]],
        exc_value: typing.Optional[BaseException],
        exc_traceback: typing.Optional[types.TracebackType],
    ) -> None:
        """Context manager exitpoint."""
        self.remove()

    def create(self: 'BuildTree') -> None:
        """\
        This method ensures that the tree exists, along with all of its
        subdirectories.
        """
        self.root.mkdir()
        self.src_root.mkdir()
        self.out_root.mkdir()
        self.out_opt.mkdir()
        self.out_app.mkdir()
        self.out_app_bin.mkdir()
        self.out_app_scripts.mkdir()
        self.out_app_share.mkdir()
        self.out_etc.mkdir()
        self.out_etc_crond.mkdir()
        self.out_etc_default.mkdir()
        self.debian_root.mkdir()

    def remove(self: 'BuildTree') -> None:
        """\
        This method deletes the filesystem tree.
        """
        shutil.rmtree(self.root)

    def output_files(self: 'BuildTree') -> list[Path]:
        """\
        This method returns the list of files that will be distributed by the
        Debian package.
        """
        return [
            self.out_app_bin_executable,
            self.out_app_scripts_cron,
            self.out_app_share_pubkey,
            self.out_app_share_provenance,
            self.out_etc_crond_crontab,
            self.out_etc_default_rapidblock,
        ]

    def debian_files(self: 'BuildTree') -> list[Path]:
        """\
        This method returns the list of files that will form the Debian
        package's control data.
        """
        return [
            self.debian_control,
            self.debian_conffiles,
            self.debian_md5sums,
            self.debian_sha1sums,
            self.debian_sha256sums,
        ]

    def unpack_source_tar(self: 'BuildTree', path: Path) -> None:
        """\
        This method unpacks the given .tar.gz archive file containing
        RapidBlock's source code.
        """
        cmd = [
            'tar',
            '--no-same-owner',
            '--no-same-permissions',
            '--same-order',
            '--no-acls',
            '--no-selinux',
            '--no-xattrs',
            '--extract',
            '--auto-compress',
            f'--file={path}',
            '--strip-components=1',
        ]
        subprocess.run(cmd, check=True, cwd=self.src_root)

    def size_in_kibibytes(self: 'BuildTree') -> int:
        """\
        This method computes the size of the filesystem tree in KiB.
        """
        cmd_tar = [
            'tar',
            '--create',
            '--mtime=2022-01-01 00:00:00',
            '--mode=u=rwX,go=rX',
            '--owner=root',
            '--group=root',
            '--sort=name',
            '.',
        ]
        cmd_wc = ['wc', '-c']
        cwd = os.fspath(self.out_root)
        with subprocess.Popen(
            cmd_tar,
            stdout=PIPE,
            cwd=cwd,
        ) as popen_tar:
            with subprocess.Popen(
                cmd_wc,
                stdin=popen_tar.stdout,
                stdout=PIPE,
            ) as popen_wc:
                _, _ = popen_tar.communicate()
                stdout, _ = popen_wc.communicate()
                rc_tar = popen_tar.returncode
                rc_wc = popen_wc.returncode
                if rc_tar != 0:
                    raise subprocess.CalledProcessError(
                        returncode=rc_tar,
                        cmd=cmd_tar,
                    )
                if rc_wc != 0:
                    raise subprocess.CalledProcessError(
                        returncode=rc_wc,
                        cmd=cmd_wc,
                        output=stdout,
                    )
        size_bytes = int(stdout.decode(ASCII).strip())
        return (size_bytes + 1023) // 1024

    def checksum(self: 'BuildTree', checksum: ChecksumName) -> None:
        """\
        This method creates the Debian checksum file of the given type.
        """
        prog_dict = {
            CHECKSUM_NAME_MD5: 'md5sum',
            CHECKSUM_NAME_SHA1: 'sha1sum',
            CHECKSUM_NAME_SHA256: 'sha256sum',
        }
        path_dict = {
            CHECKSUM_NAME_MD5: self.debian_md5sums,
            CHECKSUM_NAME_SHA1: self.debian_sha1sums,
            CHECKSUM_NAME_SHA256: self.debian_sha256sums,
        }
        prog = prog_dict[checksum]
        path = path_dict[checksum]
        root = self.out_root
        cmd = [prog, '-b', '--']
        cmd.extend(
            os.fspath(it.relative_to(root)) for it in self.output_files()
        )
        with open(path, 'wb') as handle:
            subprocess.run(cmd, check=True, stdout=handle, cwd=root)

    def build_deb(self: 'BuildTree', path: Path) -> None:
        """\
        This method builds the Debian package.
        """
        cmd = [
            'dpkg-deb',
            '--root-owner-group',
            '--build',
            os.fspath(self.out_root),
            os.fspath(path),
        ]
        subprocess.run(cmd, check=True)


def _log(level: LogLevel, message: str) -> None:
    """\
    This function logs a message.
    """
    now = datetime.datetime.now(tz=TZ)
    nowstr = now.isoformat(' ', timespec='seconds')
    print(f'[{nowstr}] {level:5s} {message}')


def info(message: str) -> None:
    """\
    This function logs a message with severity INFO.
    """
    _log(LOG_LEVEL_INFO, message)


def warn(message: str) -> None:
    """\
    This function logs a message with severity WARN.
    """
    _log(LOG_LEVEL_WARN, message)


def error(message: str) -> None:
    """\
    This function logs a message with severity ERROR.
    """
    _log(LOG_LEVEL_ERROR, message)


def arch_to_debian_arch(arch: ArchName) -> str:
    """\
    This function returns the Debian arch name for the given GOARCH.
    """
    return arch


def version_to_debian_version(version: VersionDict) -> str:
    """\
    This function returns the Debian version string for the given VersionDict.
    """
    major = version['major']
    minor = version['minor']
    patch = version['patch']
    prerelease = version['prerelease']
    out = f'{major}.{minor}.{patch}'
    if prerelease:
        out += f'-{prerelease}'
    return out


def download_asset(url: str, path: Path) -> None:
    """\
    This function downloads the GitHub release asset to the requested path.
    """
    if path.exists():
        return

    info(f'download_asset: {url}')
    req: typing.Optional[urllib3.response.HTTPResponse] = None
    is_ok = False
    try:
        with open(path, 'wb') as asset_file:
            req = POOL_MANAGER.request('GET', url, preload_content=False)
            assert req is not None
            while True:
                data = req.read(4096)
                if not data:
                    break
                asset_file.write(data)
        is_ok = True
    finally:
        if req:
            req.release_conn()
        if not is_ok:
            os.unlink(path)


def load_release_data() -> tuple[list[str], dict[str, ReleaseDict]]:
    """\
    This function loads the latest release data from the GitHub repository,
    downloading any assets that aren't present locally.
    """
    github_repo = github.Github(GITHUB_TOKEN).get_repo(GITHUB_USER + '/' + GITHUB_REPO)

    changed = False
    tags: list[str] = []
    releases_by_tag: dict[str, ReleaseDict] = {}
    data_path = DOWNLOAD_DIR / 'data.json'
    if data_path.exists():
        releases_by_tag = json.loads(data_path.read_text(encoding=UTF8))

    for github_release in github_repo.get_releases():
        if github_release.draft:
            continue

        tag_name = github_release.tag_name
        if tag_name in releases_by_tag:
            tags.append(tag_name)
            continue

        version = parse_version_dict(tag_name)
        if version is None:
            warn(f'unable to parse tag {tag_name!r} as "v" + semver')
            continue

        release: ReleaseDict = {
            'tag': tag_name,
            'title': github_release.title,
            'body': github_release.body,
            'version': version,
            'assets': [
                make_asset_dict(
                    github_release.tarball_url,
                    'source.tar.gz',
                    type=ASSET_TYPE_SOURCE_TAR,
                ),
                make_asset_dict(
                    github_release.zipball_url,
                    'source.zip',
                    type=ASSET_TYPE_SOURCE_ZIP,
                ),
            ],
        }
        release['assets'].extend(
            make_asset_dict(
                github_asset.browser_download_url,
                github_asset.name,
            )
            for github_asset in github_release.get_assets()
        )

        for asset in release['assets']:
            asset_path = DOWNLOAD_DIR / tag_name / asset['name']
            asset_path.parent.mkdir(exist_ok=True)
            download_asset(asset['url'], asset_path)

            if (asset['type'] == ASSET_TYPE_EXECUTABLE
                    and asset['os'] == OS_NAME_LINUX
                    and asset['arch'] == ARCH_NAME_AMD64):
                asset_path.chmod(0o755)
                if version['build'] is None:
                    build = extract_build_id(asset_path)
                    if build:
                        update_version_dict_build(version, build)

        releases_by_tag[tag_name] = release
        tags.append(tag_name)
        changed = True

    if changed:
        data_path_tmp = data_path.parent / '.data.json~'
        try:
            data_text = json.dumps(releases_by_tag, indent=2)
            data_path_tmp.write_text(data_text, encoding=UTF8)
            data_path_tmp.rename(data_path)
        finally:
            data_path_tmp.unlink(missing_ok=True)

    return tags, releases_by_tag


class FoundAssets(typing.NamedTuple):
    """\
    This named tuple represents the return value for "find_assets".
    """
    source_tar: str
    executable: str
    provenance: str


def find_assets(
    release: ReleaseDict,
    asset_os: OSName,
    asset_arch: ArchName,
) -> typing.Optional[FoundAssets]:
    """\
    This function returns the relevant asset filenames for the given release,
    GOOS, and GOARCH.
    """
    source_tar: typing.Optional[str] = None
    executable: typing.Optional[str] = None
    provenance: typing.Optional[str] = None
    for asset in release['assets']:
        if asset['type'] == ASSET_TYPE_SOURCE_TAR:
            source_tar = asset['name']
        elif asset['type'] == ASSET_TYPE_EXECUTABLE:
            if (asset['base'] == 'rapidblock'
                    and asset['os'] == asset_os
                    and asset['arch'] == asset_arch):
                executable = asset['name']
        elif asset['type'] == ASSET_TYPE_PROVENANCE:
            if (asset['base'] == 'rapidblock'
                    and asset['os'] == asset_os
                    and asset['arch'] == asset_arch):
                provenance = asset['name']
    if source_tar and executable and provenance:
        return FoundAssets(source_tar=source_tar, executable=executable, provenance=provenance)
    return None


def build_debian_package(
    debfiles: list[str],
    release: ReleaseDict,
    asset_os: OSName,
    asset_arch: ArchName,
) -> None:
    """\
    This function builds the Debian package for the given release, GOOS, and
    GOARCH if it does not already exist.
    """
    found_assets = find_assets(release, asset_os, asset_arch)
    if not found_assets:
        return

    debarch = arch_to_debian_arch(asset_arch)
    debversion = version_to_debian_version(release['version'])
    debfile_name = f'rapidblock_{debversion}_{debarch}.deb'
    debfile_path = REPREPRO_INCOMING / debfile_name
    if debfile_path.exists():
        return

    source_tar_path = DOWNLOAD_DIR / release['tag'] / found_assets.source_tar
    executable_path = DOWNLOAD_DIR / release['tag'] / found_assets.executable
    provenance_path = DOWNLOAD_DIR / release['tag'] / found_assets.provenance

    info(f'building {debfile_path}')

    with BuildTree(BUILD_DIR) as tree:
        tree.unpack_source_tar(source_tar_path)

        tree.out_app_bin_executable.write_bytes(executable_path.read_bytes())
        tree.out_app_bin_executable.chmod(0o755)
        tree.out_app_scripts_cron.write_bytes(tree.src_dist_cron_sh.read_bytes())
        tree.out_app_scripts_cron.chmod(0o755)
        tree.out_app_share_pubkey.write_bytes(tree.src_dist_pubkey.read_bytes())
        tree.out_app_share_provenance.write_bytes(provenance_path.read_bytes())
        tree.out_etc_crond_crontab.write_bytes(tree.src_dist_cron_tab.read_bytes())
        tree.out_etc_default_rapidblock.write_bytes(tree.src_dist_cron_default.read_bytes())

        size_kibibytes = tree.size_in_kibibytes()

        control_text = tree.src_dist_debian_control.read_text(encoding=UTF8)
        control_text = control_text.format(arch=debarch, version=debversion, size=size_kibibytes)
        tree.debian_control.write_text(control_text, encoding=UTF8)
        tree.debian_conffiles.write_bytes(tree.src_dist_debian_conffiles.read_bytes())

        tree.checksum(CHECKSUM_NAME_MD5)
        tree.checksum(CHECKSUM_NAME_SHA1)
        tree.checksum(CHECKSUM_NAME_SHA256)
        tree.build_deb(debfile_path)
        debfiles.append(os.fspath(debfile_path))


def update_apt_repo(debfiles: list[str]) -> None:
    """\
    This function updates the APT repository to publish the generated Debian
    packages.
    """
    cmd: list[str]

    cmd = ['reprepro', '--export=never', 'includedeb', DISTRIBUTION]
    cmd.extend(debfiles)
    subprocess.run(cmd, check=True, cwd=REPREPRO_DIR, capture_output=True)

    cmd = ['reprepro', 'export', DISTRIBUTION]
    subprocess.run(cmd, check=True, cwd=REPREPRO_DIR, capture_output=True)


def main() -> None:
    """Main function."""

    os.umask(0o022)
    os.environ['SOURCE_DATE_EPOCH'] = str(EPOCH)
    os.environ['GNUPGHOME'] = os.fspath(GNUPG_HOME)

    DOWNLOAD_DIR.mkdir(exist_ok=True)
    REPREPRO_DIR.mkdir(exist_ok=True)
    REPREPRO_CONF.mkdir(exist_ok=True)
    REPREPRO_INCOMING.mkdir(exist_ok=True)
    OUT_DIR.mkdir(exist_ok=True)

    if not REPREPRO_CONF_DISTRIBUTIONS.exists():
        text = TEMPLATE_DISTRIBUTIONS.read_text(encoding=UTF8)
        text = text.format(key_id=GNUPG_KEY)
        REPREPRO_CONF_DISTRIBUTIONS.write_text(text, encoding=UTF8)

    if not REPREPRO_CONF_OPTIONS.exists():
        text = TEMPLATE_OPTIONS.read_text(encoding=UTF8)
        text = text.format(
            basedir=os.fspath(REPREPRO_DIR),
            outdir=os.fspath(OUT_DIR),
        )
        REPREPRO_CONF_OPTIONS.write_text(text, encoding=UTF8)

    cmd: list[str]

    if not OUT_GPGKEY_ASC.exists():
        cmd = [
            'gpg',
            '--armor',
            '--output',
            os.fspath(OUT_GPGKEY_ASC),
            '--export',
            GNUPG_KEY,
        ]
        subprocess.run(cmd, check=True)

    if not OUT_GPGKEY_GPG.exists():
        cmd = [
            'gpg',
            '--output',
            os.fspath(OUT_GPGKEY_GPG),
            '--export',
            GNUPG_KEY,
        ]
        subprocess.run(cmd, check=True)

    tags, releases_by_tag = load_release_data()
    debfiles: list[str] = []

    for tag in tags:
        release = releases_by_tag[tag]
        build_debian_package(debfiles, release, 'linux', 'amd64')
        build_debian_package(debfiles, release, 'linux', 'arm64')

    if debfiles:
        update_apt_repo(debfiles)

    if PUBLISH_SCRIPT.exists():
        cmd = [os.fspath(PUBLISH_SCRIPT)]
        subprocess.run(cmd, check=True, cwd=OUT_DIR)


if __name__ == '__main__':
    main()
