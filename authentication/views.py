from .models import User, OTP
from datetime import timedelta
from django.utils import timezone
from django.conf import settings

import jwt

from rest_framework.response import Response
from rest_framework.decorators import api_view

from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit


@api_view(['POST'])
@csrf_exempt
def register(request):
    email = request.POST.get('email')
    password = request.POST.get('password')

    if not email or not password:
        return Response({"error": "Email and password are required."}, status=400)

    try:
        User.objects.create_user(email=email, password=password)
    except ValueError as e:
        return Response({"error": "Cannot create user."}, status=400)

    return Response({"message": "Registration successful. Please verify your email."}, status=200)


@api_view(['POST'])
@ratelimit(key='ip', rate='10/m', method='POST', block=True)
@csrf_exempt
def request_otp(request):
    email = request.POST.get('email')

    if not email:
        return Response({"error": "Email is required."}, status=400)
    
    try:
        User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"error": "User not found."}, status=404)

    otp = OTP.create(user_email=email, validity_minutes=5)
    print(f"OTP for user {email}: {otp.otp_code}")

    return Response({"message": "OTP sent to your email."}, status=200)


@api_view(['POST'])
@ratelimit(key='ip', rate='10/m', method='POST', block=True)
@csrf_exempt
def verify_otp(request):
    email = request.POST.get('email')
    otp = request.POST.get('otp')

    if not email or not otp:
        return Response({"error": "Email and OTP are required."}, status=400)

    try:  
        user = User.objects.get(email=email)
        if OTP.verify(user_email=email, otp_code=otp):
            payload = {
                'user_id': user.id,
                'exp': timezone.now() + timedelta(days=1),
                'iat': timezone.now(),
            }
            jwt_token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
            return Response({"message": "Login successful.", "token": jwt_token}, status=200)
        else:
            return Response({"error": "Invalid or expired OTP."}, status=400)
    except User.DoesNotExist:
        return Response({"error": "User not found."}, status=404)
