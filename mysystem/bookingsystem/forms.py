from django import forms
from .models import data

class userform(forms.ModelForm):
    class Meta:
        model=data
        fields=['username','email','status']
        
class PasswordResetForm(forms.Form):
    email = forms.EmailField(label="Email", max_length=254)
