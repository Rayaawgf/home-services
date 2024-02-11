# urls.py

from django.urls import path
from .  import  views

urlpatterns = [
    path('employees/', views.employee_list),
    path('employees/<int:pk>/', views.get_employee_detail),
    path('employees/<int:pk>/update/', views.update_employee_detail),
    path('employees/<int:pk>/delete/', views.delete_employee_detail),
    path('reservations/', views.reservation_list),
    path('reservations/<int:pk>/', views.reservation_detail),
    path('reservations/create/', views.create_reservation),
    path('reservations/<int:pk>/delete/', views.delete_reservation),
    path('reservations/<int:pk>/update/', views.update_reservation),
    path('authenticate/', views.authenticate_user, name='authenticate_user'),
    path('register/', views.register_user, name='register_user'),
    path('custom_users/', views.custom_user_list, name='custom_user_list'),
    path('custom_users/<int:pk>/', views.get_custom_user, name='get_custom_user_detail'),
    path('custom_users/create/', views.create_custom_user, name='create_custom_user'),
    path('custom_users/update/<int:pk>/', views.update_custom_user, name='update_custom_user_detail'),
    path('custom_users/delete/<int:pk>/', views.delete_custom_user, name='delete_custom_user'),
    
]
