from django.contrib import admin
from .models import admin_data,data

# Register your models here.
admin.site.register(data)
admin.site.register(admin_data)
