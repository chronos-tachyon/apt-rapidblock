#!/usr/bin/env python3

import datetime
import json
import os
import os.path
import re
import shutil
import subprocess
import sys
import time

from pathlib import Path

import github
import pytz
import tzlocal
import urllib3

RE_ASSET = re.compile(r'^(?P<base>rapidblock)-(?P<os>linux)-(?P<arch>(?:amd64|arm64))(?P<ext>(?:\.exe|\.intoto\.jsonl)?)$')
RE_TAG = re.compile(r'^v(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\.(?P<patch>0|[1-9][0-9]*)(?:-(?P<prerelease>(?:0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*))*))?$')
RE_VCS_REVISION = re.compile(r'^\tbuild\tvcs\.revision=([0-9a-f]{40})$')

ROOT_DIR = Path(sys.argv[0]).parent
TEMPLATE_DIR = ROOT_DIR / 'template'
TEMPLATE_CONTROL = TEMPLATE_DIR / 'control'
TEMPLATE_DISTRIBUTIONS = TEMPLATE_DIR / 'distributions'
TEMPLATE_OPTIONS = TEMPLATE_DIR / 'options'
STATIC_DIR = ROOT_DIR / 'static'
STATIC_CONFFILES = STATIC_DIR / 'conffiles'
STATIC_CRON_SH = STATIC_DIR / 'cron.sh'
STATIC_CRONTAB = STATIC_DIR / 'crontab'
STATIC_DEFAULT = STATIC_DIR / 'default'
STATIC_PUBKEY = STATIC_DIR / 'public_key'
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
GITHUB_TOKEN = open(GITHUB_TOKEN_PATH).readline().strip()
GITHUB_USER = 'chronos-tachyon'
GITHUB_REPO = 'rapidblock'

TZ = tzlocal.get_localzone()
EPOCH = 1640995200
HTTP = urllib3.PoolManager()


def log(level: str, message: str, *args, **kwargs):
    now = datetime.datetime.now(tz=TZ)
    nowstr = now.isoformat(' ', timespec='seconds')
    if args or kwargs:
        message = message.format(*args, **kwargs)
    print('[{}] {:5s} {}'.format(now, level, message))


def download_asset(asset: github.GitReleaseAsset, path: Path):
    if not path.exists():
        log('info', 'download_asset: {!r}', asset.browser_download_url)
        r = HTTP.request('GET', asset.browser_download_url, preload_content=False)
        ok = False
        try:
            with open(path, 'wb') as fp:
                while True:
                    data = r.read(4096)
                    if not data:
                        break
                    fp.write(data)
            ok = True
        finally:
            r.release_conn()
            if not ok:
                os.unlink(path)


def load_release_data():
    g = github.Github(GITHUB_TOKEN)
    repo = g.get_repo(GITHUB_USER + '/' + GITHUB_REPO)

    releases = []

    for rel in repo.get_releases():
        if rel.draft:
            continue

        rel_data_dir = DOWNLOAD_DIR / rel.tag_name
        rel_data_dir.mkdir(exist_ok=True)

        rel_data_path = rel_data_dir / 'data.json'
        if rel_data_path.exists():
            with open(rel_data_path, 'r') as fp:
                rel_data = json.load(fp)
            releases.append(rel_data)
            continue

        tag = rel.tag_name
        title = rel.title
        body = rel.body

        matchTag = RE_TAG.match(tag)
        if not matchTag:
            log('warn', 'unable to parse tag {!r} as \'v\' + semver', tag)
            continue

        ver_major = int(matchTag.group('major'))
        ver_minor = int(matchTag.group('minor'))
        ver_patch = int(matchTag.group('patch'))
        ver_prerelease = matchTag.group('prerelease')
        if not ver_prerelease:
            ver_prerelease = None

        rel_data = {
            'tag': tag,
            'title': title,
            'body': body,
            'version': {
                'full': None,
                'major': ver_major,
                'minor': ver_minor,
                'patch': ver_patch,
                'prerelease': ver_prerelease,
                'build': None,
            },
            'assets': [],
        }

        ver_build = None
        for asset in rel.get_assets():
            matchAsset = RE_ASSET.match(asset.name)
            if not matchAsset:
                continue

            asset_base = matchAsset.group('base')
            asset_os = matchAsset.group('os')
            asset_arch = matchAsset.group('arch')
            asset_ext = matchAsset.group('ext')

            asset_data = {
                'base': asset_base,
                'os': asset_os,
                'arch': asset_arch,
                'ext': asset_ext,
            }
            rel_data['assets'].append(asset_data)

            asset_path = rel_data_dir / asset.name
            download_asset(asset, asset_path)

            is_executable = (asset_base == 'rapidblock' and asset_ext in ('', '.exe'))

            if is_executable:
                asset_path.chmod(0o755)

            if is_executable and ver_build is None:
                cmd = ['go', 'version', '-m', os.fspath(asset_path)]
                p = subprocess.run(cmd, check=True, capture_output=True)
                go_version_stdout = p.stdout.decode('utf-8')
                for line in go_version_stdout.split('\n'):
                    line = line.rstrip(' \t\r\n')
                    matchVcsRevision = RE_VCS_REVISION.match(line)
                    if matchVcsRevision:
                        ver_build = matchVcsRevision.group(1)
                        break

        ver_full = '{:d}.{:d}.{:d}'.format(ver_major, ver_minor, ver_patch)
        if ver_prerelease:
            ver_full += '-' + ver_prerelease
        if ver_build:
            ver_full += '+' + ver_build
        rel_data['version']['full'] = ver_full
        rel_data['version']['build'] = ver_build

        rel_data_tmp = rel_data_path.parent / '.tmp.{}~'.format(rel_data_path.name)
        try:
            with open(rel_data_tmp, 'w') as fp:
                json.dump(rel_data, fp, indent=2)
            rel_data_tmp.rename(rel_data_path)
        finally:
            rel_data_tmp.unlink(missing_ok=True)
        releases.append(rel_data)

    return releases


def arch_to_debian_arch(arch: str) -> str:
    return arch


def version_to_debian_version(version) -> str:
    major = version['major']
    minor = version['minor']
    patch = version['patch']
    prerelease = version['prerelease']
    suffix = '-{}'.format(prerelease) if prerelease else ''
    return '{}.{}.{}{}'.format(major, minor, patch, suffix)


def build_debian_package(debfiles: list[str], release, asset_os: str, asset_arch: str):
    debarch = arch_to_debian_arch(asset_arch)
    debversion = version_to_debian_version(release['version'])
    debfile_path = REPREPRO_INCOMING / 'rapidblock_{}_{}.deb'.format(debversion, debarch)
    if debfile_path.exists():
        debfiles.append(os.fspath(debfile_path))
        return

    release_dir = DOWNLOAD_DIR / release['tag']
    skip_file = release_dir / 'skip'
    if skip_file.exists():
        return

    log('info', 'building {!r}', os.fspath(debfile_path))
    executable = 'rapidblock-{}-{}'.format(asset_os, asset_arch)
    provenance = executable + '.intoto.jsonl'
    have_executable = False
    have_provenance = False
    for asset in release['assets']:
        if asset['base'] == 'rapidblock' and asset['os'] == asset_os and asset['arch'] == asset_arch and asset['ext'] == '':
            have_executable = True
        if asset['base'] == 'rapidblock' and asset['os'] == asset_os and asset['arch'] == asset_arch and asset['ext'] == '.intoto.jsonl':
            have_provenance = True
    if not have_executable:
        log('error', 'tag={!r} os={!r} arch={!r}: missing required asset: {!r}', release['tag'], asset_os, asset_arch, executable)
        return
    if not have_provenance:
        log('error', 'tag={!r} os={!r} arch={!r}: missing required asset: {!r}', release['tag'], asset_os, asset_arch, provenance)
        return

    executable_path = release_dir / executable
    provenance_path = release_dir / provenance

    build_root = BUILD_DIR
    build_opt = BUILD_DIR / 'opt'
    build_app = build_opt / 'rapidblock'
    build_app_bin = build_app / 'bin'
    build_app_bin_executable = build_app_bin / 'rapidblock'
    build_app_scripts = build_app / 'scripts'
    build_app_scripts_cron = build_app_scripts / 'cron.sh'
    build_app_share = build_app / 'share'
    build_app_share_pubkey = build_app_share / 'rapidblock-dot-org.pub'
    build_app_share_provenance = build_app_share / 'rapidblock.intoto.jsonl'
    build_etc = BUILD_DIR / 'etc'
    build_etc_crond = build_etc / 'cron.d'
    build_etc_crond_crontab = build_etc_crond / 'rapidblock'
    build_etc_default = build_etc / 'default'
    build_etc_default_rapidblock = build_etc_default / 'rapidblock'

    debian_root = BUILD_DIR / 'DEBIAN'
    debian_control = debian_root / 'control'
    debian_conffiles = debian_root / 'conffiles'
    debian_md5sums = debian_root / 'md5sums'
    debian_sha256sums = debian_root / 'sha256sums'

    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)

    BUILD_DIR.mkdir()
    BUILD_DIR.chmod(0o755)
    build_opt.mkdir()
    build_app.mkdir()
    build_app_bin.mkdir()
    build_app_bin_executable.write_bytes(executable_path.read_bytes())
    build_app_bin_executable.chmod(0o755)
    build_app_scripts.mkdir()
    build_app_scripts_cron.write_bytes(STATIC_CRON_SH.read_bytes())
    build_app_scripts_cron.chmod(0o755)
    build_app_share.mkdir()
    build_app_share_pubkey.write_bytes(STATIC_PUBKEY.read_bytes())
    build_app_share_provenance.write_bytes(provenance_path.read_bytes())
    build_etc.mkdir()
    build_etc_crond.mkdir()
    build_etc_crond_crontab.write_bytes(STATIC_CRONTAB.read_bytes())
    build_etc_default.mkdir()
    build_etc_default_rapidblock.write_bytes(STATIC_DEFAULT.read_bytes())

    cmd0 = [
        'tar',
        '--create',
        '--mtime=2022-01-01 00:00:00',
        '--mode=u=rwX,go=rX',
        '--owner=root',
        '--group=root',
        '--sort=name',
        '.',
    ]
    cmd1 = ['wc', '-c']
    p0 = subprocess.Popen(cmd0, stdout=subprocess.PIPE, cwd=BUILD_DIR)
    p1 = subprocess.Popen(cmd1, stdin=p0.stdout, stdout=subprocess.PIPE)
    _, _ = p0.communicate()
    stdout, _ = p1.communicate()
    if p0.returncode != 0:
        log('error', 'tag={!r} os={!r} arch={!r}: command failed: {!r}: rc={}', release['tag'], asset_os, asset_arch, cmd0, p0.returncode)
        return
    if p1.returncode != 0:
        log('error', 'tag={!r} os={!r} arch={!r}: command failed: {!r}: rc={}', release['tag'], asset_os, asset_arch, cmd1, p1.returncode)
        return
    size_bytes = int(stdout.decode('ascii').strip())
    size_kibibytes = (size_bytes + 1023) // 1024

    debian_root.mkdir()
    debian_control.write_text(
        TEMPLATE_CONTROL.read_text().format(
            arch=debarch,
            version=debversion,
            size=size_kibibytes,
        )
    )
    debian_conffiles.write_bytes(STATIC_CONFFILES.read_bytes())

    cmd = [
        'md5sum',
        '-b',
        '--',
        build_app_bin_executable.relative_to(BUILD_DIR),
        build_app_scripts_cron.relative_to(BUILD_DIR),
        build_app_share_pubkey.relative_to(BUILD_DIR),
        build_app_share_provenance.relative_to(BUILD_DIR),
        build_etc_crond_crontab.relative_to(BUILD_DIR),
        build_etc_default_rapidblock.relative_to(BUILD_DIR),
    ]
    with open(debian_md5sums, 'wb') as fp:
        subprocess.run(cmd, check=True, stdout=fp, cwd=BUILD_DIR)

    cmd = [
        'sha256sum',
        '-b',
        '--',
        build_app_bin_executable.relative_to(BUILD_DIR),
        build_app_scripts_cron.relative_to(BUILD_DIR),
        build_app_share_pubkey.relative_to(BUILD_DIR),
        build_app_share_provenance.relative_to(BUILD_DIR),
        build_etc_crond_crontab.relative_to(BUILD_DIR),
        build_etc_default_rapidblock.relative_to(BUILD_DIR),
    ]
    with open(debian_sha256sums, 'wb') as fp:
        subprocess.run(cmd, check=True, stdout=fp, cwd=BUILD_DIR)

    cmd = [
        'dpkg-deb',
        '--root-owner-group',
        '--build',
        os.fspath(BUILD_DIR),
        os.fspath(debfile_path),
    ]
    subprocess.run(cmd, check=True)
    debfiles.append(os.fspath(debfile_path))
    shutil.rmtree(BUILD_DIR)


def update_apt_repo(debfiles: list[str]):
    argv = ['reprepro', '--export=never', 'includedeb', DISTRIBUTION]
    argv.extend(debfiles)
    subprocess.run(argv, check=True, cwd=REPREPRO_DIR, capture_output=True)

    argv = ['reprepro', 'export', DISTRIBUTION]
    subprocess.run(argv, check=True, cwd=REPREPRO_DIR, capture_output=True)


os.umask(0o022)
os.environ['SOURCE_DATE_EPOCH'] = str(EPOCH)
os.environ['GNUPGHOME'] = os.fspath(GNUPG_HOME)

DOWNLOAD_DIR.mkdir(exist_ok=True)
REPREPRO_DIR.mkdir(exist_ok=True)
REPREPRO_CONF.mkdir(exist_ok=True)
REPREPRO_INCOMING.mkdir(exist_ok=True)
OUT_DIR.mkdir(exist_ok=True)

if not REPREPRO_CONF_DISTRIBUTIONS.exists():
    REPREPRO_CONF_DISTRIBUTIONS.write_text(TEMPLATE_DISTRIBUTIONS.read_text().format(key_id=GNUPG_KEY))

if not REPREPRO_CONF_OPTIONS.exists():
    REPREPRO_CONF_OPTIONS.write_text(
        TEMPLATE_OPTIONS.read_text().format(
            basedir=os.fspath(REPREPRO_DIR),
            outdir=os.fspath(OUT_DIR),
        )
    )

if not OUT_GPGKEY_ASC.exists():
    cmd = ['gpg', '--armor', '--output', os.fspath(OUT_GPGKEY_ASC), '--export', GNUPG_KEY]
    subprocess.run(cmd, check=True)

if not OUT_GPGKEY_GPG.exists():
    cmd = ['gpg', '--output', os.fspath(OUT_GPGKEY_GPG), '--export', GNUPG_KEY]
    subprocess.run(cmd, check=True)

releases = load_release_data()
debfiles = []

for rel in releases:
    build_debian_package(debfiles, rel, 'linux', 'amd64')
    build_debian_package(debfiles, rel, 'linux', 'arm64')

if debfiles:
    update_apt_repo(debfiles)

if PUBLISH_SCRIPT.exists():
    cmd = [os.fspath(PUBLISH_SCRIPT)]
    subprocess.run(cmd, check=True, cwd=OUT_DIR)
