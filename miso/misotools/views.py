from django.shortcuts import render
from django.contrib import auth as authD
from django.conf import settings
from django.shortcuts import redirect
import os, requests, json, firebase_admin
from firebase_admin import credentials, auth
from . import forms


#########################
#Firebase credentials:#TODO put credentials in enviroment variable.
apiKey = os.environ.get('apiKey', default="")
authDomain = os.environ.get('authDomain', default="")
projectId = os.environ.get('projectId', default="") 
storageBucket = os.environ.get('storageBucket', default="") 
messagingSenderId = os.environ.get('messagingSenderId', default="") 
appId = os.environ.get('appId', default="") 
firebase_json_file = os.environ.get('FIREBASE_SERVICE_ACCOUNT', default=".json")

authorized_email_domains = os.environ.get('authorized_email_domains', default=['']) #If only specific email domains are authorized to register in App, list domains here (example: "@tesla.com"). If empty, all domains are authorized.

#########################
#Firebase endpoints:
firebase_rest_api_url_signIn = 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={}'.format(apiKey)
firebase_rest_api_url_emailVerification = "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode"
firebase_rest_api_url_sendResetEmail = 'https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={}'.format(apiKey)

########################
databaseURL = "https://{}.firebaseio.com".format(projectId) #In tutorial example: "databaseURL": "https://databaseName.firebaseio.com",

config = {
  "apiKey": apiKey,
  "authDomain": authDomain,
  "databaseURL":databaseURL,
  "storageBucket": storageBucket,
  "serviceAccount": firebase_json_file,
}

cred = credentials.Certificate(firebase_json_file)
firebase_admin.initialize_app(cred, {'databaseURL': databaseURL})

#db = firebase.database()#If firebase database is used for additional fields in user registration/authentication
#If only specific email domains are authorized to register in App, list domains here (example: "@tesla.com"). If empty, all domains are authorized.

#global variables:
post_register_message = False
post_top_message = False

###FUNCTIONS:
##Functions to create user, login, and verify email address:
def create_user(Email, pwd, display_name):
    new_user = auth.create_user(email=Email, email_verified=False, password=pwd, display_name=display_name, disabled=False)
    return new_user

def sign_in_with_email_and_password(Email, pwd):
    payload = json.dumps({
        "email": Email,
        "password": pwd,
        "returnSecureToken": True
    })
    r = requests.post(firebase_rest_api_url_signIn,
                      params={"key": apiKey},
                      data=payload)
    return r.json()

def send_email_verification_link(id_token):
    payload = json.dumps({
        "requestType": "VERIFY_EMAIL",
        "idToken": id_token
    })
    r = requests.post(firebase_rest_api_url_emailVerification,
                      params={"key": apiKey},
                      data=payload)
    return r.json()

def SendResetEmail(email):
    headers = {
        'Content-Type': 'application/json',
    }
    data={"requestType":"PASSWORD_RESET","email":email}
    r = requests.post(firebase_rest_api_url_sendResetEmail, data=data)
    if 'error' in r.json().keys():
        return {'status':'error','message':r.json()['error']['message']}
    if 'email' in r.json().keys():
        return {'status':'success','email':r.json()['email']}

###AUTH PAGES:
#register new users:
def register(request):
    global post_register_message
    authD.logout(request)
    if request.method == 'POST':
        register_form = forms.RegisterForm(request.POST)
        if register_form.is_valid():
            print ("Form is valid")
            first_name = register_form.cleaned_data['first_name']
            last_name = register_form.cleaned_data['last_name']
            display_name = first_name + " " + last_name
            Company = register_form.cleaned_data['Company']
            Email_reg = register_form.cleaned_data['Email_reg']
            pwd_reg = register_form.cleaned_data['pwd_reg']
            verify_pwd = register_form.cleaned_data['verify_pwd']
    
            if pwd_reg != verify_pwd:
                return_message = "Passwords don't match. Try again."
                return render(request, 'misotools/register.html', {'register_form': register_form, 'message':return_message}) 
            else:
                pass

            if len(authorized_email_domains) == 0:
                try:
                    new_user = create_user(Email_reg, pwd_reg, display_name)
                    uid = new_user.uid
                    print('New user account has been created. ID: {0}'.format(uid))
                    additional_claims = {
                                        'First_name':first_name,
                                        'Last_name':last_name,
                                        'Company':Company,
                                        'AccountTier': 1##Can add more claims here if needed:
                                    }
                    auth.set_custom_user_claims(uid, additional_claims)
                    login_user = sign_in_with_email_and_password(Email_reg, pwd_reg)#try to login to get idToken to be able to send email verification link.
                    send_email_verification_link(login_user['idToken'])
                    post_register_message = 'Account successfully created. Check your email (and spam folder) to verify account.'  
                    authD.logout(request)
                    return redirect(login)

                except Exception as e: 
                    if 'The user with the provided email already exists' in str(e):
                        return_message = "There's an existing account associated with this email."
                    else:
                        return_message = str(e)           
                    return render(request, 'misotools/register.html', {'register_form': register_form, 'message':return_message}) 
            else:
                for i in authorized_email_domains:
                    if i in Email_reg:
                        try:
                            new_user = create_user(Email_reg, pwd_reg, display_name)
                            uid = new_user.uid
                            print('New user account has been created. ID: {0}'.format(uid))
                            additional_claims = {
                                                'First_name':first_name,
                                                'Last_name':last_name,
                                                'Company':Company,
                                                'AccountTier': 1
                                            }
                            auth.set_custom_user_claims(uid, additional_claims)
                            login_user = sign_in_with_email_and_password(Email_reg, pwd_reg)#try to login to get idToken to be able to send email verification link.
                            send_email_verification_link(login_user['idToken'])
                            post_register_message = "Account created. Check your email (and spam folder) to verify your account."
                            authD.logout(request)
                            return redirect(login)

                        except Exception as e: 
                            if 'The user with the provided email already exists' in str(e):
                                return_message = "There's an existing account associated with this email."
                            else:
                                return_message = str(e)        
                            return render(request, 'misotools/register.html', {'register_form': register_form, 'message':return_message})  
                    else: pass
                return_message = "This organization hasn't been approved to create an account. Please contact support."
                return render(request, 'misotools/register.html', {'register_form': register_form, 'message':return_message})  
        else:
            print ('Form is not valid.')
            return render(request, 'misotools/register.html', {'register_form': register_form})
    else:
        register_form = forms.RegisterForm()
        return render(request, 'misotools/register.html', {'register_form': register_form})

def login(request):
    global post_register_message, post_top_message
    authD.logout(request)    
    if request.method == 'POST':
        login_form = forms.LoginForm(request.POST)
        if login_form.is_valid():
            Email = login_form.cleaned_data['Email_l']#the "Email" string needs to match to the name of the variable in the forms.py file (it gets the data from that file)
            pwd = login_form.cleaned_data['pwd_l']#the "pwd" string needs to match to the name of the variable in the forms.py file (it gets the data from that file)
            sign_in_user = sign_in_with_email_and_password(Email, pwd)
            if 'error' in sign_in_user.keys():
                if 'EMAIL_NOT_FOUND' in sign_in_user['error']['message']:
                    return_message = 'Email not found in our system. Please register first.'
                    return render(request, 'misotools/login.html', {'login_form':login_form, 'message':return_message})
                    
                elif 'INVALID_PASSWORD' in sign_in_user['error']['message']:
                    return_message = 'Invalid login credentials. Try again.'
                    return render(request, 'misotools/login.html', {'login_form':login_form,'message':return_message})
            else:
                user = auth.get_user_by_email(Email)
                account = firebase_admin.auth.get_user(user.uid)
                if account.email_verified == True:             
                    decoded_token = auth.verify_id_token(sign_in_user['idToken'])
                    uid = decoded_token['uid']
                    request.session['uid'] = str(uid)#Request session key for authentication in all pages 
                    if request.session.has_key('uid'):#If it has key, send to main page
                        return redirect(home)
                    else:
                        print ('Session key not found.')
                        return render(request, 'misotools/login.html', {'login_form':login_form})                
                else:
                    return_message = 'Check your email (and spam folder) to verify your account.'
                    return render(request, 'misotools/login.html', {'login_form':login_form, 'message':return_message})
        else:
            print('Not a valid form')
    else:
        login_form = forms.LoginForm()
    if post_register_message == False and post_top_message == False:
        return render(request, 'misotools/login.html', {'login_form':login_form}) 
    elif post_register_message != False and post_top_message== False:
        msg = post_register_message
        post_register_message = False
        return render(request, 'misotools/login.html', {'login_form':login_form, 'post_register_message':msg})   
    elif post_register_message == False and post_top_message != False:
        msg = post_top_message
        post_top_message = False
        return render(request, 'misotools/login.html', {'login_form':login_form, 'post_register_message':msg}) 
    else:
        return render(request, 'misotools/login.html', {'login_form':login_form})                

def recovery(request):
    global post_top_message
    authD.logout(request)
    if request.method == 'POST':
        recovery_form = forms.RecoveryForm(request.POST)
        if recovery_form.is_valid():
            Email = recovery_form.cleaned_data['Email_rec']
            response = SendResetEmail(Email)
            if response['status']== 'success':
                post_top_message = 'Email sent with password reset instructions. Check your spam folder too.'
                return redirect(login)
            else:
                print('Email not found')
                msg = 'There is no account associated with this email address.'
                return render(request, 'misotools/recovery.html', {'recovery_form':recovery_form, "post_top_message":msg})
        else:
            print ('Recovery form is not valid')
    else:        
        recovery_form = forms.RecoveryForm()
    return render(request, 'misotools/recovery.html', {'recovery_form':recovery_form})

def resend(request):
    global post_register_message, post_top_message
    authD.logout(request)    
    if request.method == 'POST':
        resend_form = forms.ResendForm(request.POST)
        if resend_form.is_valid():
            Email = resend_form.cleaned_data['Email_res']#the "Email" string needs to match to the name of the variable in the forms.py file (it gets the data from that file)
            pwd = resend_form.cleaned_data['pwd_res']#the "pwd" string needs to match to the name of the variable in the forms.py file (it gets the data from that file)
            sign_in_user = sign_in_with_email_and_password(Email, pwd)
            if 'error' in sign_in_user.keys():
                if 'EMAIL_NOT_FOUND' in sign_in_user['error']['message']:
                    return_message = 'Email not found in our system. Please register first.'
                    return render(request, 'misotools/resend.html', {'resend_form':resend_form, 'message':return_message})
                    
                elif 'INVALID_PASSWORD' in sign_in_user['error']['message']:
                    return_message = 'Invalid password. Try again.'
                    return render(request, 'misotools/resend.html', {'resend_form':resend_form,'message':return_message})
            else:
                user = auth.get_user_by_email(Email)
                account = firebase_admin.auth.get_user(user.uid)
                if account.email_verified == False:
                    send_email_verification_link(sign_in_user['idToken'])
                    decoded_token = auth.verify_id_token(sign_in_user['idToken'])
                    uid = decoded_token['uid']
                    request.session['uid'] = str(uid)#Request session key for authentication in all pages 
                    if request.session.has_key('uid'):#If it has key, send to main page
                        post_top_message = 'Email re-sent. Check your inbox (and spam folder) to verify your account.'
                        return redirect(login)
                    else:
                        print ('Session key not found.')
                        return render(request, 'misotools/resend.html', {'resend_form':resend_form})                
                else:
                    post_top_message = 'This email is already verified. Please login.'
                    return redirect(login)
        else:
            print('Not a valid form')
    else:
        resend_form = forms.ResendForm()
    return render(request, 'misotools/resend.html', {'resend_form':resend_form})  

def logout(request):
    global post_top_message
    try:
        del request.session['uid']
    except:
        pass
    try:
        authD.logout(request)
    except:
        pass
    post_top_message = 'You have been logged out.'
    return redirect(login)

###APP pages:
# Create your views here.
def home(request):
    if request.session.has_key('uid'):
        user = auth.get_user(request.session['uid'])
        full_name = user.custom_claims.get('First_name') + ' ' + user.custom_claims.get('Last_name')
        account_tier = user.custom_claims.get('AccountTier')

        return render(request, 'misotools/welcome.html', {"full_name" : full_name}) 
    else:
        return redirect(login)

