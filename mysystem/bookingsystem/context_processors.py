# myapp/context_processors.py
from django.urls import resolve

def role_choose_page(request):
    current_url_name = resolve(request.path_info).url_name
    return {
        'is_role_choose_page': current_url_name == 'role',
    }
