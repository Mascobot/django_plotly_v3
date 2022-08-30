from django import forms 
from django.core import validators
from django.contrib.auth.password_validation import validate_password

class LoginForm(forms.Form):
    Email_l = forms.EmailField(max_length=100)#The name of the "Email" variable needs to match with the "name=" variable in the input filed in the html template
    pwd_l = forms.CharField(widget=forms.PasswordInput(),
                                validators=[validate_password])#The name of the "pwd" variable needs to match with the "name=" variable in the input filed in the html template
    catcher_l = forms.CharField(required=False, widget=forms.HiddenInput(),
                                validators=[validators.MaxLengthValidator(0)])
    #Add classes to the input fields (to look better)
    Email_l.widget.attrs.update({'class':'form-control'})
    pwd_l.widget.attrs.update({'class':'form-control'})
    

class RegisterForm(forms.Form):
    first_name = forms.CharField(widget=forms.TextInput(), max_length = 100)
    last_name = forms.CharField(widget=forms.TextInput(), max_length = 100)
    Company = forms.CharField(required=False, widget=forms.TextInput(), max_length = 100)
    Email_reg = forms.EmailField(max_length = 100)
    pwd_reg = forms.CharField(widget=forms.PasswordInput(), validators=[validate_password])
    verify_pwd = forms.CharField(widget=forms.PasswordInput())
    catcher_reg = forms.CharField(required=False, widget=forms.HiddenInput(),
                                validators=[validators.MaxLengthValidator(0)])
    #Add classes to the input fields (to look better)
    first_name.widget.attrs.update({'class':'form-control'})
    last_name.widget.attrs.update({'class':'form-control'})
    Company.widget.attrs.update({'class':'form-control'})
    Email_reg.widget.attrs.update({'class':'form-control'})
    pwd_reg.widget.attrs.update({'class':'form-control'})
    verify_pwd.widget.attrs.update({'class':'form-control'})
                            
class RecoveryForm(forms.Form):
    Email_rec = forms.EmailField(max_length = 100)
    catcher_rec = forms.CharField(required=False, widget=forms.HiddenInput(),
                                validators=[validators.MaxLengthValidator(0)])
    
    #Add classes to the input fields (to look better)
    Email_rec.widget.attrs.update({'class':'form-control'})

class ResendForm(forms.Form):
    Email_res = forms.EmailField(max_length = 100)
    pwd_res = forms.CharField(widget=forms.PasswordInput(), validators=[validate_password])
    catcher_res = forms.CharField(required=False, widget=forms.HiddenInput(),
                                validators=[validators.MaxLengthValidator(0)])
    
    #Add classes to the input fields (to look better)
    Email_res.widget.attrs.update({'class':'form-control'})
    pwd_res.widget.attrs.update({'class':'form-control'})
    


