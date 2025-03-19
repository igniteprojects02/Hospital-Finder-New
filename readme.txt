hospital finder 
Hospital Finder is a web application that helps clients locate hospitals, book doctor appointments, and manage medical history


python version: Python 3.11.9

three users Admin, Hospital, Client

python code:
home page code at app/routes/home_routes.py
admin side code at app/routes/admin_routes.py
hospital side code at app/routes/hospital_routes.py
client side code at app/routes/client_routes.py
routes are defined in app/routes/__init__.py


to RUN this project:
1. navigate to the project directory eg:- cd hospital_finder
2.activate the virtual environment eg:- hf_env\Scripts\activate
3. install all packages\libraries using command : pip install -r requirements.txt
4. run the project using command : flask run --debug
5. open the browser and navigate to http://127.0.0.1:5000/ #(homepage)

admin credentials:
username: admin
password: admin@123


hospital credentials:
"username": amrutha2
"password": amrutha@1234

"username": lissie
"password": lissie123


client credentials:
username:Lal
password:Lal@123


data base path: hospital_finder\instance\hospital_finder.db
db configured at app/config.py
