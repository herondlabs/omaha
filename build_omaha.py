# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import glob
import os
import os.path
import shutil
import subprocess as sp
import sys

SUPPORTED_LANGUAGE = ["en", "vi"]

def config_address():
  '''
  Replaces all instances of "OMAHA_URL" in the const_addresses.h file with the url
  given by the environment variable OMAHA_URL
  '''
  omaha_url = os.environ.get('OMAHA_URL', 'https://updates.herond.org')
  omaha_dir = os.path.dirname(os.path.abspath(__file__))
  omaha_url_header = os.path.join(omaha_dir,  "omaha", "base", "omaha_url_address.h")
  with open(omaha_url_header, "w", encoding="utf-8") as f:
      f.write(f'#define OMAHA_URL "{omaha_url}"\n')

def _find_x64_signtool():
  """Return the path to the x64 signtool.exe, preferring Windows Kits over PATH."""
  wk_root = os.path.join(
      os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'),
      'Windows Kits', '10', 'bin')
  matches = sorted(
      glob.glob(os.path.join(wk_root, '*', 'x64', 'signtool.exe')),
      reverse=True)  # highest SDK version first
  signtool_path = matches[0] if matches else shutil.which('signtool.exe')
  
  if not signtool_path or not os.path.exists(signtool_path):
    print("[ERROR] signtool.exe not found in Windows Kits or PATH. Halting build.", file=sys.stderr)
    sys.exit(1)

  print(f"[INFO] Using signtool from: {signtool_path}")
  return signtool_path

def build(omaha_dir, standalone_installers_dir, debug):
  # move to omaha/omaha and start build.
  os.chdir(os.path.join(omaha_dir, 'omaha'))

  # set signing environment variables
  key_pfx_path = os.environ.get('KEY_PFX_PATH', '')
  key_cer_path = os.environ.get('KEY_CER_PATH', '')
  authenticode_password = os.environ.get('AUTHENTICODE_PASSWORD', '')
  authenticode_hash = os.environ.get('AUTHENTICODE_HASH', '')
  csp = os.environ.get('CER_SCP', '')

  # HSM / Cloud KMS signing variables (new path, takes priority when set).
  # HSM_CRT_PATH          - path to the public .crt certificate file
  # HSM_KMS_KEY_CONTAINER - key container string (e.g. GCP KMS resource path)
  # HSM_CSP               - CSP name (default: "Google Cloud KMS Provider")
  # SIGN_TIMESTAMP_SERVER - timestamp URL (default: http://timestamp.sectigo.com)
  hsm_crt_path = os.environ.get('HSM_CRT_PATH', '')
  hsm_kms_key_container = os.environ.get('HSM_KMS_KEY_CONTAINER', '')
  hsm_csp = os.environ.get('HSM_CSP', 'Google Cloud KMS Provider')
  hsm_timestamp_server = os.environ.get('SIGN_TIMESTAMP_SERVER', 'http://timestamp.sectigo.com')

  mode = 'dbg-win' if debug else 'opt-win'
  command = ['hammer.bat', 'MODE=' + mode, '--all', '--standalone_installers_dir=' + standalone_installers_dir]

  if hsm_kms_key_container:
    # HSM / Cloud KMS signing: single SHA256 pass via signtool /kc.
    if hsm_crt_path:
      command.append('--hsm_authenticode_file=' + hsm_crt_path)
    command.append('--hsm_csp=' + hsm_csp)
    command.append('--hsm_key_container=' + hsm_kms_key_container)
    command.append('--hsm_timestamp_server=' + hsm_timestamp_server)
  else:
    # update sign flag following: https://stackoverflow.com/questions/17927895/automate-extended-validation-ev-code-signing-with-safenet-etoken
    if key_cer_path:
      command.append('--authenticode_file=' + key_cer_path)
      command.append('--sha1_authenticode_file=' + key_cer_path)
      command.append('--sha2_authenticode_file=' + key_cer_path)
    if authenticode_password:
      command.append('--authenticode_password=' + authenticode_password)
      command.append('--sha1_authenticode_password=' + authenticode_password)
      command.append('--sha2_authenticode_password=' + authenticode_password)
    if authenticode_hash:
      command.append('--authenticode_hash=' + authenticode_hash)
      command.append('--sha1_authenticode_hash=' + authenticode_hash)
      command.append('--sha2_authenticode_hash=' + authenticode_hash)
      # Our certs identified by hash are always in the machine store:
      command.append('--use_authenticode_machine_store')

    if csp:
      command.append('--sha1_csp=' + csp)
      command.append('--sha2_csp=' + csp)

  # Prefer the x64 signtool so that it can load the 64-bit Google Cloud KMS
  # CNG provider DLL.  Fall back to whatever is on PATH.  Write directly to
  # os.environ so hammer.bat inherits it through the full process env block
  # (passing env= to check_call creates an isolated block that vcvarsall.bat
  # can strip when it does its internal 'endlocal & set' dance).
  signtool_path = _find_x64_signtool()
  assert signtool_path, 'signtool.exe (x64) not found in Windows Kits or PATH'
  os.environ['OMAHA_SIGNTOOL_SDK_DIR'] = os.path.dirname(signtool_path)

  # No env= here: subprocess inherits the full Windows process environment,
  # including APPDATA (provided by Windows for user-mode processes) and all
  # vars set above via os.environ.
  sp.check_call(command, stderr=sp.STDOUT)

def _sign_brave_installer(installer_path):
  """Sign herond_installer.exe in place using the Google Cloud KMS HSM provider.

  Delegates to src/herond/script/sign_windows_hsm.py, the canonical HSM
  signing script.  Signing is skipped when HSM credentials are absent (e.g.
  local dev builds) without error.

  The file is signed in place.  build_omaha_installer no longer declares
  herond_installer.exe in its GN `sources`, so there is no Siso file-lock
  race.  Siso will mark create_signed_installer stale on the next incremental
  build (its recorded output hash changes), but that target is a fast COPY
  and the re-run is harmless.
  """
  hsm_kms_key_container = os.environ.get('HSM_KMS_KEY_CONTAINER', '')
  hsm_crt_path = os.environ.get('HSM_CRT_PATH', '')
  if not (hsm_kms_key_container and hsm_crt_path):
    print(f"[INFO] HSM credentials not set, skipping signing of "
          f"{os.path.basename(installer_path)}")
    return

  # Locate sign_windows_hsm.py relative to this script.
  # build_omaha.py lives at src/brave/vendor/omaha/build_omaha.py;
  # sign_windows_hsm.py lives at src/herond/script/sign_windows_hsm.py.
  script_dir = os.path.dirname(os.path.abspath(__file__))
  sign_script = os.path.normpath(
      os.path.join(script_dir, '..', '..', '..', 'herond', 'script',
                   'sign_windows_hsm.py'))

  print(f"[INFO] Signing {os.path.basename(installer_path)} via "
        f"sign_windows_hsm.py ...")
  sp.check_call([sys.executable, sign_script, installer_path],
                stderr=sp.STDOUT)
  print(f"[INFO] Signing complete: {installer_path}")


def copy_untagged_installers(args, omaha_dir):
  omaha_out_dir = get_omaha_out_dir(omaha_dir, args.debug)

  source_untagged_installer = os.path.join(omaha_out_dir, 'Test_Installers', 'UNOFFICIAL_' + args.untagged_installer_exe[0])
  target_untagged_installer_file = args.untagged_installer_exe[0]
  if args.debug:
    target_untagged_installer_file = 'Debug' + target_untagged_installer_file
  target_untagged_installer = os.path.join(args.root_out_dir[0], target_untagged_installer_file)

  shutil.copyfile(source_untagged_installer, target_untagged_installer)

  source_untagged_stub_installer = os.path.join(omaha_out_dir, 'staging', 'HerondUpdateSetup.exe')
  target_untagged_stub_installer_file = args.stub_untagged_exe[0]
  if args.debug:
    target_untagged_stub_installer_file = 'Debug' + target_untagged_stub_installer_file
  target_untagged_stub_installer = os.path.join(args.root_out_dir[0], target_untagged_stub_installer_file)

  shutil.copyfile(source_untagged_stub_installer, target_untagged_stub_installer)

def get_omaha_out_dir(omaha_dir, debug):
  last_win_dir = 'dbg-win' if debug else 'opt-win'
  return os.path.join(omaha_dir, 'omaha', 'scons-out', last_win_dir)

def prepare_untagged_standalone(args, omaha_dir):
  return prepare_untagged(
    omaha_dir, 'standalone', args.root_out_dir[0], args.brave_installer_exe[0], args.guid[0],
    '--do-not-launch-chrome ' + args.install_switch[0], args.brave_full_version[0],
    [(args.standalone_installer_exe[0], args.brave_installer_exe[0]),
     (args.untagged_installer_exe[0], args.untagged_installer_exe[0])], args.debug
  )

def prepare_untagged_silent(args, omaha_dir):
  return prepare_untagged(
    omaha_dir, 'silent', args.root_out_dir[0], args.brave_installer_exe[0], args.guid[0],
    '--do-not-launch-chrome ' + args.install_switch[0], args.brave_full_version[0],
    [(args.silent_installer_exe[0], args.silent_installer_exe[0])], args.debug
  )

def prepare_untagged(omaha_dir, name, root_out_dir, brave_installer_exe, app_guid, install_switch, brave_full_version, details, debug):
  omaha_out_dir = get_omaha_out_dir(omaha_dir, debug)
  out_dir = os.path.join(omaha_out_dir, 'Herond_Installers', name)

  if not os.path.exists(out_dir):
    os.makedirs(out_dir)

  # For beta version (x.y.z.t) => The pv should be [chromium_major].x.y.(z*100 + t)
  # If version has 5 components (chrome_major.x.y.z.t), calculate beta patch: z*100 + t
  version_parts = brave_full_version.split('.')
  if len(version_parts) == 5:
    # Beta version: calculate z*100 + t where z = version_parts[3], t = version_parts[4] (or 0 if empty)
    z = int(version_parts[3])
    t = int(version_parts[4]) if version_parts[4] and version_parts[4].strip() else 0
    beta_patch = z * 100 + t
    brave_full_version = '.'.join(version_parts[:3]) + '.' + str(beta_patch)

  # prepare manifest file.
  f = open(os.path.join(omaha_dir, 'manifest_template.gup'),'r')
  filedata = f.read()
  f.close()

  newdata = filedata.replace("APP_GUID", app_guid)
  newdata = newdata.replace("HEROND_INSTALLER_EXE", brave_installer_exe)
  newdata = newdata.replace("INSTALL_SWITCH", install_switch)

  target_manifest_dir = os.path.join(out_dir, 'manifests')

  if not os.path.exists(target_manifest_dir):
    os.mkdir(target_manifest_dir)

  target_manifest_file = app_guid + '.gup'
  target_manifest_path = os.path.join(target_manifest_dir, target_manifest_file)
  f = open(target_manifest_path, 'w')
  f.write(newdata)
  f.close()

  target_installer_text_path = os.path.join(out_dir, 'standalone_installers.txt')

  # Clear the file:
  open(target_installer_text_path, 'w').close()

  for file_name, installer_exe in details:
    brave_installer_path = os.path.join(root_out_dir, brave_installer_exe)
    brave_installer_path_fixed_name = os.path.join(out_dir, installer_exe)
    shutil.copyfile(brave_installer_path, brave_installer_path_fixed_name)
    add_to_standalone_installers_txt(target_installer_text_path, file_name, app_guid, brave_installer_path_fixed_name, brave_full_version)

  return out_dir

def add_to_standalone_installers_txt(target_installer_text_path, file_name, app_guid, installer_exe_path, brave_version):
  installer_text = "('FILE_NAME', 'FILE_NAME', [('HEROND_VERSION', 'HEROND_INSTALLER_EXE', 'APP_GUID')], None, None, None, False, '', '')"
  installer_text = installer_text.replace("FILE_NAME", os.path.splitext(file_name)[0])
  installer_text = installer_text.replace("APP_GUID", app_guid)
  installer_text = installer_text.replace("HEROND_INSTALLER_EXE", installer_exe_path.replace('\\', '/'))
  installer_text = installer_text.replace("HEROND_VERSION", brave_version)
  f = open(target_installer_text_path,'a+')
  f.write(installer_text + '\n')
  f.close()

def tag_standalone(args, omaha_dir):
  tag_admin = os.environ.get('TAG_ADMIN', 'prefers')
  tag = 'appguid=APP_GUID&appname=TAG_APP_NAME&lang=TAG_LANG&needsadmin=TAG_ADMIN&ap=TAG_AP'
  tag = tag.replace("TAG_ADMIN", tag_admin)
  tag = tag.replace("APP_GUID", args.guid[0])
  tag = tag.replace("TAG_APP_NAME", args.tag_app_name[0])
  tag = tag.replace("TAG_AP", args.tag_ap[0])
  if not (args.tag_lang[0] and args.tag_lang[0].strip()) or args.tag_lang[0] == 'all':
    for lang in SUPPORTED_LANGUAGE:
        ltag = tag.replace("TAG_LANG", lang)
        out_dir = os.path.join(args.root_out_dir[0], "lang", lang)
        apply_tag(omaha_dir, args.debug, 'Test_Installers/UNOFFICIAL_' + args.standalone_installer_exe[0], args.standalone_installer_exe[0], ltag, out_dir)
        apply_tag(omaha_dir, args.debug, 'staging/HerondUpdateSetup.exe', args.stub_installer_exe[0], ltag, out_dir)
  else:
      language = args.tag_lang[0].split(',')
      for lang in language:
        ltag = tag.replace("TAG_LANG", lang)
        out_dir = os.path.join(args.root_out_dir[0], "lang", lang)
        apply_tag(omaha_dir, args.debug, 'Test_Installers/UNOFFICIAL_' + args.standalone_installer_exe[0], args.standalone_installer_exe[0], ltag, out_dir)
        apply_tag(omaha_dir, args.debug, 'staging/HerondUpdateSetup.exe', args.stub_installer_exe[0], ltag, out_dir)

def tag_silent(args, omaha_dir):
  silent_tag = 'appguid=APP_GUID&appname=TAG_APP_NAME&lang=TAG_LANG&needsadmin=TAG_ADMIN&ap=TAG_AP&silent'
  silent_tag = silent_tag.replace("TAG_ADMIN", 'False')
  silent_tag = silent_tag.replace("APP_GUID", args.guid[0])
  silent_tag = silent_tag.replace("TAG_APP_NAME", args.tag_app_name[0])
  silent_tag = silent_tag.replace("TAG_AP", args.tag_ap[0])

  if not (args.tag_lang[0] and args.tag_lang[0].strip()) or args.tag_lang[0] == 'all':
    for lang in SUPPORTED_LANGUAGE:
        ltag = silent_tag.replace("TAG_LANG", lang)
        out_dir = os.path.join(args.root_out_dir[0], "lang", lang)
        apply_tag(omaha_dir, args.debug, 'Test_Installers/UNOFFICIAL_' + args.silent_installer_exe[0], args.silent_installer_exe[0], ltag, out_dir)
  else:
      language = args.tag_lang[0].split(',')
      for lang in language:
        ltag = silent_tag.replace("TAG_LANG", lang)
        out_dir = os.path.join(args.root_out_dir[0], "lang", lang)
        apply_tag(omaha_dir, args.debug, 'Test_Installers/UNOFFICIAL_' + args.silent_installer_exe[0], args.silent_installer_exe[0], ltag, out_dir)

def apply_tag(omaha_dir, debug, source_installer, target_installer_file, tag, root_out_dir):
  omaha_out_dir = get_omaha_out_dir(omaha_dir, debug)
  apply_tag_exe = os.path.join(omaha_out_dir, 'obj', 'tools', 'ApplyTag', 'ApplyTag.exe')

  source_installer_path = os.path.join(omaha_out_dir, *source_installer.split('/'))
  if debug:
    target_installer_file = 'Debug' + target_installer_file
  target_installer_path = os.path.join(root_out_dir, target_installer_file)
  command = [apply_tag_exe, source_installer_path, target_installer_path, tag]
  sp.check_call(command, stderr=sp.STDOUT)

def parse_args():
  parser = argparse.ArgumentParser(description='build omaha installer')
  parser.add_argument('--root_out_dir',
                      nargs=1)
  parser.add_argument('--brave_installer_exe',
                      nargs=1)
  parser.add_argument('--stub_installer_exe',
                      nargs=1)
  parser.add_argument('--stub_untagged_exe',
                      nargs=1)
  parser.add_argument('--standalone_installer_exe',
                      nargs=1)
  parser.add_argument('--silent_installer_exe',
                      nargs=1)
  parser.add_argument('--untagged_installer_exe',
                      nargs=1)
  parser.add_argument('--guid',
                      nargs=1)
  parser.add_argument('--install_switch',
                      nargs=1)
  parser.add_argument('--tag_ap',
                      nargs=1)
  parser.add_argument('--tag_app_name',
                      nargs=1)
  parser.add_argument("--tag_lang",
                      nargs=1)
  parser.add_argument('--brave_full_version',
                      nargs=1)
  parser.add_argument(
    '--config_address',
    help=('Replaces all instances of "OMAHA_URL" in the const_addresses.h file with the url '
          'given by the environment variable OMAHA_URL'),
    action='store_true',
    default=False)
  parser.add_argument('--debug', action='store_true', default=False)
  return parser.parse_args()

def main():
  args = parse_args()

  if args.config_address:
    config_address()
  else:
    omaha_dir = os.path.join(args.root_out_dir[0], '..', '..', 'brave', 'vendor', 'omaha')
    brave_installer_path = os.path.join(
        args.root_out_dir[0], args.brave_installer_exe[0])

    # Sign herond_installer.exe in place before omaha packaging so that the
    # signed binary is embedded inside every tagged/untagged Omaha installer
    # and is also the artifact released directly as META_INSTALLER.
    _sign_brave_installer(brave_installer_path)

    installer_metadata_dir = prepare_untagged_standalone(args, omaha_dir)
    build(omaha_dir, installer_metadata_dir, args.debug)
    tag_standalone(args, omaha_dir)

    installer_metadata_dir = prepare_untagged_silent(args, omaha_dir)
    build(omaha_dir, installer_metadata_dir, args.debug)
    tag_silent(args, omaha_dir)

    copy_untagged_installers(args, omaha_dir)

  return 0


if __name__ == '__main__':
  sys.exit(main())