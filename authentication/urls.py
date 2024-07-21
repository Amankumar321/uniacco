from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('request-otp/', views.request_otp, name='request-otp'),
    path('verify-otp/', views.verify_otp, name='verify-otp'),
]
