# models.py

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin , User
from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    phone_number = models.CharField(max_length=15, unique=True)
    password = models.CharField(max_length=128)  # Champ pour stocker le mot de passe haché

    # Vous pouvez ajouter d'autres champs personnalisés ici

    def __str__(self):
        return self.username
    
    
class Category(models.Model):
    name = models.CharField(max_length=255)

class Competence(models.Model):
    name = models.CharField(max_length=255)





class Employee(models.Model):
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
    ]

    STATUS_CHOICES = [
        ('ACTIVE', 'Active'),
        ('INACTIVE', 'Inactive'),
    ]

    
    name = models.CharField(max_length=255)
    photo = models.ImageField(upload_to='employee_photos/')
    card_number = models.CharField(max_length=20)
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    nationality = models.CharField(max_length=100)
    language = models.CharField(max_length=100)
    date_of_birth = models.DateField()
    score = models.IntegerField()
    salary = models.DecimalField(max_digits=10, decimal_places=2)
    address = models.TextField()
    status = models.CharField(max_length=10, choices=STATUS_CHOICES)
    state = models.CharField(max_length=100)

    categories = models.ManyToManyField(Category)
    competences = models.ManyToManyField(Competence)

class Reservation(models.Model):
    customUser = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE)
    date = models.DateField()



