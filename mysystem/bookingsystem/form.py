from django import forms
from models import data

class userform(forms.ModelForm):
    class Meta:
        model=data
        fields=['username','email','status']
        
        
