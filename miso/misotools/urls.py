from django.urls import path
from . import views
from misotools.finished_apps import simpleexample#<-Import all plotly apps here

urlpatterns = [
path('', views.home, name='home'),
path('login', views.login, name='login'),
path('register', views.register, name='register'),
path('recovery', views.recovery, name='recovery'),
path('resend', views.resend, name='resend'),
path('logout', views.logout, name='logout'),
    ]