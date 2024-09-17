from django.db.models.signals import post_save
from django.contrib.auth.models import User
from django.dispatch import receiver
from .models import data, admin_data

@receiver(post_save, sender=User)
def create_user_related_data(sender, instance, created, **kwargs):
    if created:
        # Create a corresponding object in the `data` model
        data.objects.create(
            username=instance.username, 
            email=instance.email,
            status=[3]  # Default status value as empty list
        )
        
        # # Create a corresponding object in the `admin_data` model
        # admin_data.objects.create(
        #     user=instance,
        #     username=instance.username, 
        #     email=instance.email,
        #     status=[]  # Default status value as empty list
        # )
