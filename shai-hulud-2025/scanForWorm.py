import os
import json
import hashlib
import sys
from pathlib import Path

class LockFileNotFound(Exception):
    pass

# The known malicious bundle.js hash from the Shai-Hulud attack
MALICIOUS_BUNDLE_HASH = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"

# Dictionary of known malicious packages and their compromised versions
KNOWN_MALICIOUS_PACKAGES = {
"@ctrl/deluge": ["7.2.2", "7.2.1"],
"@ctrl/golang-template": ["1.4.3", "1.4.2"],
"@ctrl/magnet-link": ["4.0.4", "4.0.3"],
"@ctrl/ngx-codemirror": ["7.0.2", "7.0.1"],
"@ctrl/ngx-csv": ["6.0.2", "6.0.1"],
"@ctrl/ngx-emoji-mart": ["9.2.2", "9.2.1"],
"@ctrl/ngx-rightclick": ["4.0.2", "4.0.1"],
"@ctrl/qbittorrent": ["9.7.2", "9.7.1"],
"@ctrl/react-adsense": ["2.0.2", "2.0.1"],
"@ctrl/shared-torrent": ["6.3.2", "6.3.1"],
"@ctrl/tinycolor@4.1.1": ["4.1.2"],
"@ctrl/torrent-file": ["4.1.2", "4.1.1"],
"@ctrl/transmission": ["7.3.1"],
"@ctrl/ts-base32": ["4.0.2", "4.0.1"],
"@nativescript-community/gesturehandler": ["2.0.35"],
"@nativescript-community/sentry": ["4.6.43"],
"@nativescript-community/text": ["1.6.13", "1.6.10", "1.6.11", "1.6.12", "1.6.9"],
"@nativescript-community/ui-collectionview": ["6.0.6"],
"@nativescript-community/ui-drawer": ["0.1.30"],
"@nativescript-community/ui-image": ["4.5.6"],
"@nativescript-community/ui-material-bottomsheet": ["7.2.72"],
"@nativescript-community/ui-material-core": ["7.2.76", "7.2.72", "7.2.73", "7.2.74", "7.2.75"],
"@nativescript-community/ui-material-core-tabs": ["7.2.76", "7.2.72", "7.2.73", "7.2.74", "7.2.75"],
"@teselagen/bio-parsers": ["0.4.29", "0.4.30"],
"@teselagen/bounce-loader": ["0.3.16", "0.3.17"],
"@teselagen/file-utils": ["0.3.21", "0.3.22"],
"@teselagen/liquibase-tools": ["0.4.1"],
"@teselagen/ove": ["0.7.39", "0.7.40"],
"@teselagen/range-utils": ["0.3.14", "0.3.15"],
"@teselagen/react-list": ["0.8.19", "0.8.20"],
"@teselagen/react-table": ["6.10.21", "6.10.19", "6.10.20", "6.10.22"],
"@teselagen/sequence-utils": ["0.3.33", "0.3.34"],
"@teselagen/ui": ["0.9.9", "0.9.10"],
"angulartics2": ["14.1.2", "14.1.1"],
"encounter-playground": ["0.0.4", "0.0.5", "0.0.2", "0.0.3"],
"eslint-config-teselagen": ["6.1.7", "6.1.8"],
"graphql-sequelize-teselagen": ["5.3.8", "5.3.9"],
"json-rules-engine-simplified": ["0.2.3", "0.2.4", "0.2.1"],
"koa2-swagger-ui": ["5.11.2", "5.11.1"],
"ng2-file-upload": ["8.0.3", "7.0.2", "7.0.3", "8.0.1", "8.0.2", "9.0.1"],
"ngx-bootstrap": ["18.1.4", "19.0.3", "20.0.4", "20.0.5", "20.0.6", "19.0.4", "20.0.3"],
"ngx-color": ["10.0.2", "10.0.1"],
"ngx-toastr": ["19.0.2", "19.0.1"],
"ngx-trend": ["8.0.1"],
"oradm-to-gql": ["35.0.14", "35.0.15"],
"oradm-to-sqlz": ["1.1.4", "1.1.2"],
"ove-auto-annotate": ["0.0.9", "0.0.10"],
"react-complaint-image": ["0.0.34", "0.0.35", "0.0.32"],
"react-jsonschema-form-conditionals": ["0.3.20", "0.3.21", "0.3.18"],
"react-jsonschema-form-extras": ["1.0.3", "1.0.4"],
"react-jsonschema-rxnt-extras": ["0.4.8", "0.4.9"],
"rxnt-authentication": ["0.0.5", "0.0.6", "0.0.3", "0.0.4"],
"rxnt-healthchecks-nestjs": ["1.0.4", "1.0.5", "1.0.2", "1.0.3"],
"rxnt-kue": ["1.0.6", "1.0.7", "1.0.4", "1.0.5"],
"swc-plugin-component-annotate": ["1.9.2", "1.9.1"],
"tg-client-query-builder": ["2.14.4", "2.14.5"],
"tg-redbird": ["1.3.1", "1.3.2"],
"tg-seq-gen": ["1.0.9", "1.0.10"],
"ts-gaussian": ["3.0.6", "3.0.5"],
"ve-bamreader": ["0.2.6", "0.2.7"],
"ve-editor": ["1.0.1", "1.0.2"],
"@ahmedhfarag/ngx-perfect-scrollbar": ["20.0.20"],
"@ahmedhfarag/ngx-virtual-scroller": ["4.0.4"],
"@art-ws/common": ["2.0.28"],
"@art-ws/config-eslint": ["2.0.4", "2.0.5"],
"@art-ws/config-ts": ["2.0.7", "2.0.8"],
"@art-ws/db-context": ["2.0.24"],
"@art-ws/di-node": ["2.0.13"],
"@art-ws/di": ["2.0.28", "2.0.32"],
"@art-ws/eslint": ["1.0.5", "1.0.6"],
"@art-ws/fastify-http-server": ["2.0.24", "2.0.27"],
"@art-ws/http-server": ["2.0.21", "2.0.25"],
"@art-ws/openapi": ["0.1.12", "0.1.9"],
"@art-ws/package-base": ["1.0.5", "1.0.6"],
"@art-ws/prettier": ["1.0.5", "1.0.6"],
"@art-ws/slf": ["2.0.15", "2.0.22"],
"@art-ws/ssl-info": ["1.0.10", "1.0.9"],
"@art-ws/web-app": ["1.0.3", "1.0.4"],
"@crowdstrike/commitlint": ["8.1.1", "8.1.2"],
"@crowdstrike/falcon-shoelace": ["0.4.1", "0.4.2"],
"@crowdstrike/foundry-js": ["0.19.1", "0.19.2"],
"@crowdstrike/glide-core": ["0.34.2", "0.34.3"],
"@crowdstrike/logscale-dashboard": ["1.205.1", "1.205.2"],
"@crowdstrike/logscale-file-editor": ["1.205.1", "1.205.2"],
"@crowdstrike/logscale-parser-edit": ["1.205.1", "1.205.2"],
"@crowdstrike/logscale-search": ["1.205.1", "1.205.2"],
"@crowdstrike/tailwind-toucan-base": ["5.0.1", "5.0.2"],
"@ctrl/tinycolor": ["4.1.1", "4.1.2"],
"@hestjs/core": ["0.2.1"],
"@hestjs/cqrs": ["0.1.6"],
"@hestjs/demo": ["0.1.2"],
"@hestjs/eslint-config": ["0.1.2"],
"@hestjs/logger": ["0.1.6"],
"@hestjs/scalar": ["0.1.7"],
"@hestjs/validation": ["0.1.6"],
"@nativescript-community/arraybuffers": ["1.1.6", "1.1.7", "1.1.8"],
"@nativescript-community/perms": ["3.0.5", "3.0.6", "3.0.7", "3.0.8", "3.0.9"],
"@nativescript-community/sqlite": ["3.5.2", "3.5.3", "3.5.4", "3.5.5"],
"@nativescript-community/typeorm": ["0.2.30", "0.2.31", "0.2.32", "0.2.33"],
"@nativescript-community/ui-document-picker": ["1.1.27", "1.1.28", "13.0.32"],
"@nativescript-community/ui-label": ["1.3.35", "1.3.36", "1.3.37"],
"@nativescript-community/ui-material-bottom-navigation": ["7.2.72", "7.2.73", "7.2.74", "7.2.75"],
"@nativescript-community/ui-material-ripple": ["7.2.72", "7.2.73", "7.2.74", "7.2.75"],
"@nativescript-community/ui-material-tabs": ["7.2.72", "7.2.73", "7.2.74", "7.2.75"],
"@nativescript-community/ui-pager": ["14.1.36", "14.1.37", "14.1.38"],
"@nativescript-community/ui-pulltorefresh": ["2.5.4", "2.5.5", "2.5.6", "2.5.7"],
"@nexe/config-manager": ["0.1.1"],
"@nexe/eslint-config": ["0.1.1"],
"@nexe/logger": ["0.1.3"],
"@nstudio/angular": ["20.0.4", "20.0.5", "20.0.6"],
"@nstudio/focus": ["20.0.4", "20.0.5", "20.0.6"],
"@nstudio/nativescript-checkbox": ["2.0.6", "2.0.7", "2.0.8", "2.0.9"],
"@nstudio/nativescript-loading-indicator": ["5.0.1", "5.0.2", "5.0.3", "5.0.4"],
"@nstudio/ui-collectionview": ["5.1.11", "5.1.12", "5.1.13", "5.1.14"],
"@nstudio/web-angular": ["20.0.4"],
"@nstudio/web": ["20.0.4"],
"@nstudio/xplat-utils": ["20.0.5", "20.0.6", "20.0.7"],
"@nstudio/xplat": ["20.0.5", "20.0.6", "20.0.7"],
"@operato/board": ["9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46"],
"@operato/data-grist": ["9.0.29", "9.0.35", "9.0.36", "9.0.37"],
"@operato/graphql": ["9.0.22", "9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46"],
"@operato/headroom": ["9.0.2", "9.0.35", "9.0.36", "9.0.37"],
"@operato/help": ["9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46"],
"@operato/i18n": ["9.0.35", "9.0.36", "9.0.37"],
"@operato/input": ["9.0.27", "9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.47", "9.0.48"],
"@operato/layout": ["9.0.35", "9.0.36", "9.0.37"],
"@operato/popup": ["9.0.22", "9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.49"],
"@operato/pull-to-refresh": ["9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42"],
"@operato/shell": ["9.0.22", "9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39"],
"@operato/styles": ["9.0.2", "9.0.35", "9.0.36", "9.0.37"],
"@operato/utils": ["9.0.22", "9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.49"],
"@thangved/callback-window": ["1.1.4"],
"@things-factory/attachment-base": ["9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.47", "9.0.48", "9.0.49", "9.0.50", "9.0.51", "9.0.52", "9.0.53", "9.0.54", "9.0.55"],
"@things-factory/auth-base": ["9.0.42", "9.0.43", "9.0.44", "9.0.45"],
"@things-factory/email-base": ["9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.47", "9.0.48", "9.0.49", "9.0.50", "9.0.51", "9.0.52", "9.0.53", "9.0.54", "9.0.55", "9.0.56", "9.0.57", "9.0.58", "9.0.59"],
"@things-factory/env": ["9.0.42", "9.0.43", "9.0.44", "9.0.45"],
"@things-factory/integration-base": ["9.0.42", "9.0.43", "9.0.44", "9.0.45"],
"@things-factory/integration-marketplace": ["9.0.42", "9.0.43", "9.0.44", "9.0.45"],
"@things-factory/shell": ["9.0.42", "9.0.43", "9.0.44", "9.0.45"],
"@tnf-dev/api": ["1.0.8"],
"@tnf-dev/core": ["1.0.8"],
"@tnf-dev/js": ["1.0.8"],
"@tnf-dev/mui": ["1.0.8"],
"@tnf-dev/react": ["1.0.8"],
"@ui-ux-gang/devextreme-angular-rpk": ["24.1.7"],
"@yoobic/design-system": ["6.5.17"],
"@yoobic/jpeg-camera-es6": ["1.0.13"],
"@yoobic/yobi": ["8.7.53"],
"airchief": ["0.3.1"],
"airpilot": ["0.8.8"],
"browser-webdriver-downloader": ["3.0.8"],
"capacitor-notificationhandler": ["0.0.2", "0.0.3"],
"capacitor-plugin-healthapp": ["0.0.2", "0.0.3"],
"capacitor-plugin-ihealth": ["1.1.8", "1.1.9"],
"capacitor-plugin-vonage": ["1.0.2", "1.0.3"],
"capacitorandroidpermissions": ["0.0.4", "0.0.5"],
"config-cordova": ["0.8.5"],
"cordova-plugin-voxeet2": ["1.0.24"],
"cordova-voxeet": ["1.0.32"],
"create-hest-app": ["0.1.9"],
"db-evo": ["1.1.4", "1.1.5"],
"devextreme-angular-rpk": ["21.2.8"],
"ember-browser-services": ["5.0.2", "5.0.3"],
"ember-headless-form-yup": ["1.0.1"],
"ember-headless-form": ["1.1.2", "1.1.3"],
"ember-headless-table": ["2.1.5", "2.1.6"],
"ember-url-hash-polyfill": ["1.0.12", "1.0.13"],
"ember-velcro": ["2.2.1", "2.2.2"],
"eslint-config-crowdstrike-node": ["4.0.3", "4.0.4"],
"eslint-config-crowdstrike": ["11.0.2", "11.0.3"],
"globalize-rpk": ["1.7.4"],
"html-to-base64-image": ["1.0.2"],
"jumpgate": ["0.0.2"],
"mcfly-semantic-release": ["1.3.1"],
"mcp-knowledge-base": ["0.0.2"],
"mcp-knowledge-graph": ["1.2.1"],
"mobioffice-cli": ["1.0.3"],
"monorepo-next": ["13.0.1", "13.0.2"],
"mstate-angular": ["0.4.4"],
"mstate-cli": ["0.4.7"],
"mstate-dev-react": ["1.1.1"],
"mstate-react": ["1.6.5"],
"ngx-ws": ["1.1.5", "1.1.6"],
"pm2-gelf-json": ["1.0.4", "1.0.5"],
"printjs-rpk": ["1.6.1"],
"remark-preset-lint-crowdstrike": ["4.0.1", "4.0.2"],
"tbssnch": ["1.0.2"],
"teselagen-interval-tree": ["1.1.2"],
"thangved-react-grid": ["1.0.3"],
"ts-imports": ["1.0.1", "1.0.2"],
"tvi-cli": ["0.1.5"],
"verror-extra": ["6.0.1"],
"voip-callkit": ["1.0.2", "1.0.3"],
"wdio-web-reporter": ["0.1.3"],
"yargs-help-output": ["5.0.3"],
"yoo-styles": ["6.0.326"],
# September 2025 NPM Supply Chain Attack packages (from ArmorCode blog)
"backslash": ["0.2.1"],
"chalk-template": ["1.1.1"],
"supports-hyperlinks": ["4.1.1"],
"has-ansi": ["6.0.1"],
"simple-swizzle": ["0.2.3"],
"color-string": ["2.1.1"],
"error-ex": ["1.3.3"],
"color-name": ["2.0.1"],
"is-arrayish": ["0.3.3"],
"slice-ansi": ["7.1.1"],
"color-convert": ["3.1.1"],
"wrap-ansi": ["9.0.1"],
"ansi-regex": ["6.2.1"],
"supports-color": ["10.2.1"],
"strip-ansi": ["7.1.1"],
"chalk": ["5.6.1"],
"debug": ["4.4.2"],
"ansi-styles": ["6.2.2"],
"proto-tinker-wc": ["0.1.87"],
"duckdb": ["1.3.3"],
"@duckdb/node-api": ["1.3.3"],
"@duckdb/node-bindings": ["1.3.3"],
"@duckdb/duckdb-wasm": ["1.29.2"],
"@coveops/abi": ["2.0.1"],
"prebid.js": ["10.9.1", "10.9.2"],
"prebid-universal-creative": ["1.17.3"],
}

def find_malicious_packages(lock_file_path):
    "Parses a package-lock.json file to find known malicious packages."

    affected = []
    present_unaffected = []

    if not lock_file_path.exists():
        raise LockFileNotFound(f"Lock file not found: {lock_file_path}. Skipping.")

    try:
        with open(lock_file_path, 'r') as f:
            lock_data = json.load(f)

        packages = {
            k: v for k, v in lock_data.get('packages', {}).items() 
            if k.startswith('node_modules/')
        }
        for name, info in packages.items():
            package_name = name.rsplit('node_modules/', 1)[-1]
            version = info.get('version')
            # print(f"Checking package: {package_name}@{version}...")

            if package_name in KNOWN_MALICIOUS_PACKAGES:
                if version in KNOWN_MALICIOUS_PACKAGES[package_name]:
                    affected.append(f"Found known malicious package: {package_name}@{version}")
                else:
                    present_unaffected.append(f"Found package {package_name}@{version}, but version is not known to be malicious.")

    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error reading or parsing lock file: {e}")

    return affected, present_unaffected

def find_suspicious_scripts(project_path):
    "Recursively checks for suspicious 'postinstall' or 'install' scripts."
    suspicious_scripts = []
    for root, _, files in os.walk(project_path):
        if 'package.json' in files:
            pkg_json_path = os.path.join(root, 'package.json')
            try:
                with open(pkg_json_path, 'r') as f:
                    pkg_data = json.load(f)

                scripts = pkg_data.get('scripts', {})
                for script_name, script_cmd in scripts.items():
                    if script_name in ['postinstall', 'install']:
                        if 'node bundle.js' in script_cmd:
                            suspicious_scripts.append(f"Found suspicious '{script_name}' script in {pkg_json_path}: '{script_cmd}'")
            except (json.JSONDecodeError, FileNotFoundError):
                continue
    return suspicious_scripts

def check_malicious_bundle(project_path):
    "Searches for and hashes a 'bundle.js' file in the project."
    affected = []
    bundle_file_path = project_path / 'bundle.js'

    if bundle_file_path.exists():
        print(f"Checking hash for {bundle_file_path}...")
        hasher = hashlib.sha256()
        with open(bundle_file_path, 'rb') as f:
            buf = f.read()
            hasher.update(buf)
        file_hash = hasher.hexdigest()

        if file_hash == MALICIOUS_BUNDLE_HASH:
            affected.append(f"Found malicious bundle.js with hash: {file_hash}")
        else:
            print(f"Found 'bundle.js' but hash does not match known malicious hash. Hash: {file_hash}")

    return affected

def run_audit(project_path):
    "Executes all Shai-Hulud checks on the specified project path."
    project_path = Path(project_path)
    print(f"Starting Shai-Hulud audit for project at: {project_path}\n")

    results = {
        "malicious_packages": [],
        "identified_packages": [],
        "suspicious_scripts": [],
        "malicious_bundle": [],
    }

    # Check for known malicious packages in the lock file
    print("Step 1: Checking for known malicious packages...")
    affected, present_unaffected = find_malicious_packages(project_path / 'package-lock.json')
    results["malicious_packages"] = affected
    results["identified_packages"] = present_unaffected

    # Check for suspicious install scripts
    print("\nStep 2: Checking for suspicious 'postinstall' or 'install' scripts...")
    results["suspicious_scripts"] = find_suspicious_scripts(project_path)

    # Check for the malicious bundle.js file
    print("\nStep 3: Checking for the malicious 'bundle.js' file...")
    results["malicious_bundle"] = check_malicious_bundle(project_path)

    return results

if __name__ == '__main__':
    # You can specify the project path here. Defaults to the current directory.
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_project>")
        sys.exit(1)

    project_directory = Path(sys.argv[1])

    try:
        audit_results = run_audit(project_directory)
    except LockFileNotFound as e:
        print(e)
        sys.exit(1)

    print("\n--- Audit Summary ---")
    if any(audit_results.values()):
        print("Threats detected. The following potential issues were found:")
        if audit_results["malicious_packages"]:
            print("\nMalicious Packages:")
            for item in audit_results["malicious_packages"]:
                print(f"  - {item}")

        if audit_results["identified_packages"]:
            print("\nIdentified Packages:")
            for item in audit_results["identified_packages"]:
                print(f"  - {item}")

        if audit_results["suspicious_scripts"]:
            print("\nSuspicious Scripts:")
            for item in audit_results["suspicious_scripts"]:
                print(f"  - {item}")

        if audit_results["malicious_bundle"]:
            print("\nMalicious bundle.js File:")
            for item in audit_results["malicious_bundle"]:
                print(f"  - {item}")
    else:
        print("No known Shai-Hulud related threats detected in this project.")
