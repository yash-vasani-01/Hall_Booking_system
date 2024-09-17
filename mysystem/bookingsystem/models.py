from django.db import models
from django.contrib.auth.models import User
from datetime import time

class data(models.Model):
    username=models.CharField(max_length=50)
    email=models.EmailField( max_length=254)
    status=models.JSONField(blank=True, default=list)
    def __str__(self):
        return (f"{self.username}")


class admin_data(models.Model):
    INSTITUTE_CHOICES = [
        ('CSPIT', 'CSPIT'),
        ('DEPSTAR', 'DEPSTAR'),
        ('RPCP', 'RPCP'),
        ('PDPIAS', 'PDPIAS'),
        ('Ashok and Rita patel institute of physiotherapy', 'Ashok and Rita patel institute of physiotherapy'),
        ('IIIM', 'IIIM'),
        ('BDIPS', 'BDIPS'),
        ('CMPICA', 'CMPICA'),
        ('Manikaka Topawala Institute of Nursing', 'Manikaka Topawala Institute of Nursing'),    
    ]
    # user = models.OneToOneField(User, on_delete=models.CASCADE,null=True)
    username = models.CharField(max_length=150)
    email = models.EmailField(max_length=254)
    status=models.JSONField(blank=True, default=list)
    institute_name = models.CharField(max_length=255, choices=INSTITUTE_CHOICES, null=True, blank=True,unique=True) 
    
    
    def __str__(self):
        return self.username
    

class SeminarHall(models.Model):
    institute_name = models.CharField(max_length=255)
    hall_name = models.CharField(max_length=255, null=True)
    location = models.CharField(max_length=255)
    capacity = models.IntegerField()
    audio_system = models.BooleanField(default=False)
    projector = models.BooleanField(default=False)
    internet_wifi = models.BooleanField(default=False)
    
    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['institute_name', 'hall_name'], name='unique_hall_per_institute')
        ]

    def __str__(self):
        return f"{self.hall_name} ({self.institute_name})"



class BookingRequest(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
    )
    
    institute_name = models.CharField(max_length=255)  
    hall_name = models.CharField(max_length=255)  
    date = models.DateField()  
    start_time = models.TimeField(default=time(0, 0))
    end_time = models.TimeField(default=time(0, 0))  
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')  
    requester_name = models.CharField(max_length=50)  
    admin = models.ForeignKey(admin_data, on_delete=models.CASCADE,null=True)

    def __str__(self):
        return f"Request by {self.requester_name} for {self.hall_name} on {self.date} at {self.time_slot}"