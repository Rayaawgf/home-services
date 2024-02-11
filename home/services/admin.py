# admin.py

from django.contrib import admin
from .models import Category, Competence, Employee, Reservation

class EmployeeAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'gender', 'nationality', 'status', 'state')
    list_filter = ('gender', 'nationality', 'categories')

admin.site.register(Category)
admin.site.register(Competence)
admin.site.register(Employee, EmployeeAdmin)
admin.site.register(Reservation)
