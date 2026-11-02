import os
import zipfile
import hashlib

def main():
    zip_name = "tenantcache.zip"
    exclude_dirs = {
        '.git', '__pycache__', '.pytest_cache', '.hypothesis',
        'dist', 'build', 'tenantcache.egg-info', '.eggs',
        'logs', 'temp'
    }
    exclude_files = {'.DS_Store', 'desktop.ini', 'tenantcache.zip', 'tenantcache.zip.sha256', 'SHA256SUMS'}

    file_count = 0
    with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk('.'):
            # Prune excluded directories in-place
            dirs[:] = [
                d for d in dirs
                if d not in exclude_dirs and not d.endswith('.egg-info')
            ]
            
            # Additional path safety: skip if root contains 'logs' or 'temp' directory
            path_parts = set(os.path.normpath(root).split(os.sep))
            if 'logs' in path_parts or 'temp' in path_parts:
                continue

            for f in files:
                if f in exclude_files:
                    continue
                if f.endswith('.pyc') or f.endswith('.pyo'):
                    continue
                if f.endswith('.pid') or f.endswith('.log') or f.startswith('runtime_'):
                    continue
                
                full_path = os.path.join(root, f)
                arcname = os.path.relpath(full_path, '.')
                zf.write(full_path, arcname)
                file_count += 1

    with zipfile.ZipFile(zip_name, 'r') as zf:
        bad_file = zf.testzip()
        pyc_files = [n for n in zf.namelist() if n.endswith('.pyc') or n.endswith('.pyo')]
        runtime_files = [
            n for n in zf.namelist()
            if any(p in n.replace('\\', '/').split('/') for p in ['logs', 'temp'])
            or n.endswith('.pid') or n.endswith('.log')
        ]

    with open(zip_name, 'rb') as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    size_bytes = os.path.getsize(zip_name)
    size_mb = size_bytes / (1024 * 1024)

    # Write root SHA256SUMS and companion sidecar
    with open("tenantcache.zip.sha256", "w", encoding="utf-8") as f:
        f.write(f"{sha}  {zip_name}\n")

    with open("SHA256SUMS", "w", encoding="utf-8") as f:
        f.write(f"{sha}  {zip_name}\n")

    print(f"Archive created: {zip_name}")
    print(f"Total files: {file_count}")
    print(f"Integrity test: {'PASSED' if bad_file is None else f'FAILED: {bad_file}'}")
    print(f"Pyc check: {'CLEAN (0 found)' if len(pyc_files) == 0 else f'{len(pyc_files)} pyc files found'}")
    print(f"Runtime residue check: {'CLEAN (0 found)' if len(runtime_files) == 0 else f'{len(runtime_files)} runtime files found'}")
    print(f"Size: {size_bytes} bytes ({size_mb:.2f} MB)")
    print(f"SHA-256: {sha}")
    print("Generated companion sidecar tenantcache.zip.sha256 and root SHA256SUMS.")

if __name__ == "__main__":
    main()
