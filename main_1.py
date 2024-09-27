from flask import Flask, request, jsonify, render_template, send_from_directory
import requests
import json
import base64
from datetime import datetime
from wsgiref.handlers import format_date_time
from time import mktime
import hashlib
import hmac
from urllib.parse import urlencode
from flask_cors import CORS
from PIL import Image
import io
from werkzeug.utils import secure_filename
import os
import pickle
import shutil
import pymysql

app = Flask(__name__)


now = datetime.now()
nowtime=0
person_id=None                                                                          #个人的id文件夹
person_password=None                                                                    #个人的密码
app.config['UPLOAD_FOLDER'] = '/var/www/html/photonote/img_upload'                      # 存储图片的路径

CORS(app)

APPId = "d5022957"                                                                      # 控制台获取
APISecret = "NDNjOWFhYjgzYWE0NzBkNTI2ZTU2MWZj"                                          # 控制台获取
APIKey = "82d1049413f68c5105360d5582b226d9"                                             # 控制台获取

class AssembleHeaderException(Exception):
    def __init__(self, msg):
        self.message = msg

class Url:
    def __init__(self, host, path, scheme):
        self.host = host
        self.path = path
        self.scheme = scheme
        pass

def sha256base64(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    digest = base64.b64encode(sha256.digest()).decode(encoding='utf-8')
    return digest

def parse_url(requset_url):                                                             # 解析url的函数
    stidx = requset_url.index("://")                                                    # 取“：”的下标
    host = requset_url[stidx + 3:]                                                      # 取网址域名及参数
    scheme = requset_url[:stidx + 3]                                                    # scheme链接头部
    edidx = host.index("/")
    if edidx <= 0:
        raise AssembleHeaderException("invalid request url:" + requset_url)             # url中无’/‘，即网址错误
    path = host[edidx:]                                                                 # 路径
    host = host[:edidx]                                                                 # 域名
    u = Url(host, path=path, scheme=scheme)                                             # 创建Url对象
    # print(u.host,u.path,u.scheme)
    return u                                                                            # 返回Url对象

def assemble_auth_headers(url, method="POST", api_key="", api_secret=""):               # url加密函数
    u = parse_url(url)                                                                  # 解析url
    host = u.host
    path = u.path
    date = format_date_time(mktime(now.timetuple()))                                    # 取调用api时的时间并格式化

    # 鉴权操作加密过程
    signature_origin = "host: {}\ndate: {}\n{} {} HTTP/1.1".format(host, date, method, path)
    # print(signature_origin)
    signature_sha = hmac.new(api_secret.encode('utf-8'), signature_origin.encode('utf-8'),              # hmac对api_secret、路径加密
                             digestmod=hashlib.sha256).digest()
    # print(signature_sha)
    signature_sha = base64.b64encode(signature_sha).decode(encoding='utf-8')                            # 加密后的数据流转换为文本并解码
    # print(signature_sha)
    authorization_origin = "api_key=\"%s\", algorithm=\"%s\", headers=\"%s\", signature=\"%s\"" % (     # 身份信息
        api_key, "hmac-sha256", "host date request-line", signature_sha)
    # print(authorization_origin)
    authorization = base64.b64encode(authorization_origin.encode('utf-8')).decode(encoding='utf-8')     # 身份信息转换为文件并解码

    values = {                                                                                          # 将加密过后的信息存放在values字典
        "host": host,
        "date": date,
        "authorization": authorization
    }
    return url + "?" + urlencode(values)                        # 将字典字符转换为可以在网络上传输的格式并作为url的参数和url拼接起来作为返回值
 
# @app.route('/aaaa')                                             # 主页面
# def aaaa():
#     return render_template('f.html')                            # 用html渲染

@app.route('/home')                                             # 主页面
def home():
    return render_template('index.html')                        # 用html渲染

@app.route('/')                                                 #登录界面
def upload_page():
    return render_template('sign.html')

@app.route('/register')                                         #注册界面
def register():
    return render_template('register.html')

@app.route('/idget/<id>')                                       #获取id的路由
def idget(id):
    print(id)
    global person_id
    person_id=id
    return jsonify({'person_id':person_id})


@app.route('/security_check/<id>/<password>')                   #用户身份认证
def security_check(id,password):
                                                                #建立连接
    connection = pymysql.connect(host='localhost',
                             user='root',
                             password='123456',
                             database='pass',
                             cursorclass=pymysql.cursors.DictCursor)    

    
    cur = connection.cursor()                                   # 创建游标对象
    search_value = id                                           # 定义查询的变量
    sql_query = 'SELECT * FROM person_password WHERE idd = %s'   # 编写 SQL 查询语句

    try:
        cur.execute(sql_query, (search_value,))                 # 执行 SQL 语句
        results = cur.fetchall()                                # 获取所有查询结果
        security_id=0                                           #返回值，控制密码正确与否
        if(password==results[0]['password']):
            security_id=1
        else:
            security_id=0
    except Exception as e:
        security_id=2
    finally:
        cur.close()                                             # 关闭连接
        connection.close()
    
    return jsonify({'security_id':security_id})

@app.route('/id_get_route/<id>/<password>',methods=['GET'])     # 获取账号密码并存入数据库
def id_get_route(id,password):
    global person_id
    global person_password
    person_id=id
    person_password=password

    #建立连接
    connection = pymysql.connect(host='localhost',              # 与云服务器的本地mysql建立连接
                             user='root',
                             password='123456',
                             database='pass',
                             cursorclass=pymysql.cursors.DictCursor)    

    cur = connection.cursor()
    sql_insert = 'insert into person_password (idd,password) VALUES (%s,%s)'

    try:
        cur.executemany(sql_insert,[(person_id,person_password)])      #插入数据
        connection.commit()
        print("插入成功")
    except Exception as e:
        print(e)
        connection.rollback()
        print("执行插入数据失败")
    finally:
        connection.close()
        cur.close()
    return jsonify({'data':person_id})

@app.route('/id_exist/<id>',methods=['GET'])                    #查询账号存在与否
def id_exst(id):
    connection = pymysql.connect(host='localhost',
                             user='root',
                             password='123456',
                             database='pass',
                             cursorclass=pymysql.cursors.DictCursor)    

    cur = connection.cursor()
    search_value = id
    sql_query = 'SELECT * FROM person_password WHERE idd = %s'

    try:
        cur.execute(sql_query, (search_value,))
        results = cur.fetchall()
        exist=0                                                 # 不存在exist=0
        idd=results[0]
        
    except Exception as e:                                      # 新账号可以创建exist=1
        exist=1
    finally:
        cur.close()
        connection.close()
    return jsonify({'exist':exist})                             # 返回exist控制账号是否可以创建

                                                                
@app.route('/get_previous_images', methods=['GET'])             # 添加一个新的路由用于获取以往上传的图片列表
def get_previous_images():
    image_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'test',person_id)          # 拼接存储图片的文件夹路径
    images_folder = os.listdir(image_folder)                    # 获取该文件夹下的所有图片文件名 
    return jsonify({"images_folder": images_folder})

@app.route('/images_count',methods=['GET'])                     #用于计算图片数量
def images_count():
    print('进入count的route')
    image_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'test',person_id)          # 拼接存储图片的文件夹路径
    images_folder = os.listdir(image_folder)
    image_length=len(images_folder)
    return jsonify({"image_length":image_length})

@app.route('/get_image/<foldername>/<filename>', methods=['GET'])                       # 用于获取以往上传的图片
def get_image(foldername, filename):
    image_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'test',person_id,foldername)
    # print(image_folder)

    return send_from_directory(directory=image_folder, path=filename)   # send_from_dictionary()函数将指定目录文件发送的客户端


@app.route('/get_text/<foldername>/<filename>', methods=['GET'])        #获取识别过的文本      
def get_text(foldername, filename):
    text_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'test',person_id,foldername, filename)
    try:
        with open(text_file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        return jsonify({"text": content})
    except IOError:
        return jsonify({"error": "File not found"}), 404
    
@app.route('/delete_folder/<foldername>',methods=['POST'])              #删除图片的路由
def delete_folder(foldername):
    folder_path=os.path.join(app.config['UPLOAD_FOLDER'],'test',person_id,foldername)
    shutil.rmtree(folder_path)                                          # 使用 shutil.rmtree 删除文件夹
    return jsonify({"status": "success", "message": "Folder deleted successfully."}), 200


@app.route('/upload', methods=['POST'])                                 # 加载页面，调用api
def upload_file():
    print('a')
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400                  # 若没有读取到图片文件，报错error 400

    file = request.files['file']                                        # 返回file的名字，若没有名字报错
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    print('c')
    if file:                                                            # 保存上传的图片
        image_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'test')
        filename = secure_filename(file.filename)                       # 将路径中的‘/’用‘_’替代
        global nowtime      
        nowtime = datetime.now()
        nowtime =nowtime.strftime("%Y-%m-%d %H:%M:%S")
        new_folder = nowtime+filename[:-4]+'.jpg'
        path = image_folder                                             # 创建文件夹单独储存图片和识别到的文字
        os.chdir(path)
        print('e')
        print(person_id)
        new_id_folder=person_id
        print(new_id_folder)
        if not os.path.exists(new_id_folder):                           #个人用户的文件夹
            os.makedirs(new_id_folder)
        
        os.chdir(new_id_folder)                                         #打开文件夹

        if not os.path.exists(new_folder):                              #每张图片的文件夹    
            os.makedirs(new_folder)

        file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'test',person_id,new_folder, new_folder))
    print('d')
    image_bytes = file.read()                                           # 读取图片文件数据流

    ima = Image.open(file)                                              # 压缩上传的图片，达到api调用图片大小的要求
    ima1 = ima.resize((600,1200))                                       # 调整图像大小
    imgByteArr = io.BytesIO()
    
    if ima1.mode=='RGBA':                                               #当图片格式为png时，修改压缩格式确保图片上传成功
        ima1 = ima1.convert('RGB')
        save_path=os.path.join(path,person_id,new_folder)
    
    ima1.save(imgByteArr, format='JPEG')
    imgByteArr = imgByteArr.getvalue()                                  # 最终将图片转换回字符数据，方便传输

    url = 'http://api.xf-yun.com/v1/private/sf8e6aca1'                  # 调取url网址
    print('b')
    body = {                                                            # 访问请求时携带的data参数
        "header": {
            "app_id": APPId,                                            # 携带的APPID
            "status": 3
        },
        "parameter": {
            "sf8e6aca1": {
                "category": "ch_en_public_cloud",
                "result": {                                             # 请求返回的数据参数
                    "encoding": "utf8",
                    "compress": "raw",
                    "format": "json"
                }
            }
        },
        "payload": {                                                    # 请求时携带的实际照片数据
            "sf8e6aca1_data_1": {
                "encoding": "jpg",
                "image": str(base64.b64encode(imgByteArr), 'UTF-8'),    # 使用base64将数据流转换为字符串文本
                "status": 3
            }
        }
    }
    print('3434')
    request_url = assemble_auth_headers(url, "POST", APIKey, APISecret) # 对url进行加密
    headers = {                                                         # 后续访问请求时的头部数据
        'content-type': "application/json",
        'host': 'api.xf-yun.com',
        'app_id': APPId
    }  
    response = requests.post(url=request_url, data=json.dumps(body), headers=headers)  # 访问加密后的url返回的数据
    if response.status_code == 200:                                     # 访问成功与否调试
        pass
    else:
        return jsonify({"提示": "当前访问太频繁，请稍等一会再上传"}), 500

    tempResult = json.loads(response.content.decode())                  # 返回结果存储为js格式
    finalResult = base64.b64decode(tempResult['payload']['result']['text']).decode()  # 将数据中的text数据转换为文本字符并解码
    finalResult = finalResult.replace(" ", "").replace("\n", "").replace("\t", "").strip()  # 去除换行及空格
    # print("text字段Base64解码后=>" + finalResult)
    finalResult_json = json.loads(finalResult)
    if 'lines' in finalResult_json['pages'][0].keys():
        line_list = finalResult_json['pages'][0]['lines']               # 取出结果中的有用文本数据过程
        contents = []                                                   # 存放最终结果的变量
        for i in line_list:
            # print (i)
            if 'words' not in i:
                continue
            for m in i['words']:
                # print(m)
                # print(m['content'])
                contents.append(m['content'])                           # 将文本添加到contents变量中
        print(contents)
    else:
        contents='未识别到文字'
        

    if contents:                                                        # 保存识别的文字
        print(contents)
        image_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'test',person_id)  # 拼接存储图片的文件夹路径
        filename = secure_filename(file.filename)

        new_folder = nowtime+filename[:-4]+'.jpg'

        path = image_folder + '/' + new_folder
        os.chdir(path)

        with open(new_folder + '.txt', 'w')as f:                        # 创建txt文件并写入识别文字
            f.writelines(contents)
        images = os.listdir(image_folder)

    return jsonify({"recognized_text": " ".join(contents)})             # 返回json数据响应


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)                      # 启动flask，开放所有IP访问，端口为5000