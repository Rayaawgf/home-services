from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import Employee, Reservation
from django.contrib.auth.models import User
from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework import status
from django_otp.oath import totp
from django.core.cache import cache
from django.contrib.auth.hashers import make_password
import random
from .serializers import EmployeeSerializer, ReservationSerializer
import pyotp
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
from .models import CustomUser
from .serializers import CustomUserSerializer


@api_view(['GET'])
def custom_user_list(request):
    if request.method == 'GET':
        users = CustomUser.objects.all()
        serializer = CustomUserSerializer(users, many=True)
        return Response(serializer.data)


@api_view(['POST'])
def create_custom_user(request):
    if request.method == 'POST':
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def get_custom_user(request, pk):
    try:
        user = CustomUser.objects.get(pk=pk)
    except CustomUser.DoesNotExist:
        return Response({'message': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = CustomUserSerializer(user)
        return Response(serializer.data)



@api_view(['PUT'])
def update_custom_user(request, pk):
    try:
        user = CustomUser.objects.get(pk=pk)
    except CustomUser.DoesNotExist:
        return Response({'message': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        serializer = CustomUserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




@api_view(['DELETE'])
def delete_custom_user(request, pk):
    try:
        user = CustomUser.objects.get(pk=pk)
    except CustomUser.DoesNotExist:
        return Response({'message': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)






@api_view(['GET'])
def employee_list(request):
        # Récupérez les paramètres de filtre depuis la requête GET
        gender = request.GET.get('gender', None)
        nationality = request.GET.get('nationality', None)
        category = request.GET.get('category', None)

        # Filtrez les employés en fonction des critères spécifiés
        filters = {}
        if gender:
            filters['gender'] = gender
        if nationality:
            filters['nationality'] = nationality
        if category:
            filters['categories__name'] = category

        employees = Employee.objects.filter(**filters)
        serializer = EmployeeSerializer(employees, many=True)
        return Response(serializer.data)



@api_view(['GET'])
def get_employee_detail(request, pk):
    try:
        employee = Employee.objects.get(pk=pk)
    except Employee.DoesNotExist:
        return Response({'message': 'The employee does not exist'}, status=status.HTTP_404_NOT_FOUND)

    serializer = EmployeeSerializer(employee)
    return Response(serializer.data)


@api_view(['PUT'])
def update_employee_detail(request, pk):
    try:
        employee = Employee.objects.get(pk=pk)
    except Employee.DoesNotExist:
        return Response({'message': 'The employee does not exist'}, status=status.HTTP_404_NOT_FOUND)

    serializer = EmployeeSerializer(employee, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
def delete_employee_detail(request, pk):
    try:
        employee = Employee.objects.get(pk=pk)
    except Employee.DoesNotExist:
        return Response({'message': 'The employee does not exist'}, status=status.HTTP_404_NOT_FOUND)

    employee.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)



@api_view(['GET'])
def reservation_list(request):
    reservations = Reservation.objects.all()
    serializer = ReservationSerializer(reservations, many=True)
    return Response(serializer.data)



@api_view(['GET'])
def reservation_detail(request, pk):
    try:
        reservation = Reservation.objects.get(pk=pk)
    except Reservation.DoesNotExist:
        return Response({'message': 'The reservation does not exist'}, status=status.HTTP_404_NOT_FOUND)

    serializer = ReservationSerializer(reservation)
    return Response(serializer.data)


@api_view(['POST'])
def create_reservation(request):
    serializer = ReservationSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
def delete_reservation(request, pk):
    try:
        reservation = Reservation.objects.get(pk=pk)
    except Reservation.DoesNotExist:
        return Response({'message': 'The reservation does not exist'}, status=status.HTTP_404_NOT_FOUND)

    reservation.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['PUT'])
def update_reservation(request, pk):
    try:
        reservation = Reservation.objects.get(pk=pk)
    except Reservation.DoesNotExist:
        return Response({'message': 'The reservation does not exist'}, status=status.HTTP_404_NOT_FOUND)

    serializer = ReservationSerializer(reservation, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)







@api_view(['POST'])
def register_user(request):
    if request.method == 'POST':
        phone_number = request.data.get('phone_number')
        password = request.data.get('password')
        otp_code = request.data.get('otp_code')

        if not phone_number or not password or not otp_code:
            return JsonResponse({'message': 'Phone number, password, and OTP code are required'}, status=status.HTTP_400_BAD_REQUEST)

        # Vérifier si l'utilisateur existe déjà avec le même numéro de téléphone
        if User.objects.filter(username=phone_number).exists():
            return JsonResponse({'message': 'User with this phone number already exists'}, status=status.HTTP_400_BAD_REQUEST)

        # Vérifier si le code OTP est valide
        if not cache.get(phone_number) == otp_code:
            return JsonResponse({'message': 'Invalid OTP code'}, status=status.HTTP_400_BAD_REQUEST)

        # Créer un nouvel utilisateur avec le numéro de téléphone et le mot de passe fournis
        user = User.objects.create(username=phone_number, password=make_password(password))

        # Supprimer le code OTP de la cache après l'avoir utilisé
        cache.delete(phone_number)

        return JsonResponse({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)




@api_view(['POST'])
def authenticate_user(request):
    if request.method == 'POST':
        phone_number = request.data.get('phone_number')
        

        if not phone_number :
            return Response({'message': 'Phone number  are required'}, status=status.HTTP_400_BAD_REQUEST)

        # Get the user object based on the phone number
        user = get_object_or_404(CustomUser, phone_number=phone_number)

        # Generate OTP based on the user's secret key
        totp = pyotp.TOTP(user.otp_secret_key)
        if totp.verify(otp_code):
            # OTP code is valid, return success response
            return Response({'message': 'OTP code is valid'}, status=status.HTTP_200_OK)
        else:
            # OTP code is invalid, return error response
            return Response({'message': 'Invalid OTP code'}, status=status.HTTP_401_UNAUTHORIZED)