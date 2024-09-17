from django.urls import path,include
from .views import login_,logout_,register,home,record,role,welcome,admin_page,faculty_page,add_seminar_hall,get_hall_details_by_name,institute_info,book_hall,faculty_request_list,cancel_request,admin_request_list
from . import views
from allauth.account.views import LoginView  #type:ignore
from allauth.socialaccount.views import SignupView #type:ignore
from .views import CustomPasswordResetConfirmView

urlpatterns = [
    path('',welcome,name='welcome'),
    path('login/',login_,name='login'),
    path('logout/', logout_, name='logout'),
    path('register/',register,name='register'),
    path('main/',home,name='home'),
    path('record/ <int:pk>',record,name='record'),
    path('role/',role,name='role'),
    path('admin_/',admin_page,name='admin_page'),
    path('faculty/',faculty_page,name='faculty_page'),
    path('add_hall/',add_seminar_hall,name='add_hall'),
    path('get_hall_details_by_name/<str:hall_name>/<str:institute_name>/', get_hall_details_by_name, name='get_hall_details_by_name'),
    path('institute_info/<str:institute_name>/', institute_info, name='institute_info'),
    path('book_hall/<str:hall_name>/<str:institutename>/',book_hall,name='book_hall'), 
    path('your_request/',faculty_request_list,name='faculty_request'),
    path('cancel_request/<int:request_id>/',cancel_request,name='cancel_request'),
    path('request_list/',admin_request_list,name='admin_request'),
    path('captcha_image/', views.captcha_image, name='captcha_image'),
    path('accounts/google/login/callback/', LoginView.as_view(), name='google_login_callback'),
    path('login/', LoginView.as_view(), name='login'),
    path('google/login/', SignupView.as_view(), name='google_login'),
    path('accounts/', include('allauth.urls')),
    path('password_reset/', views.password_reset_request, name='password_reset'),
    path('password_reset_confirm/<int:uid>/<str:token>/', views.password_reset_confirm, name='password_reset_confirm'),
    path('password_reset_complete_close_tab/', views.password_reset_complete_close_tab, name='password_reset_complete_close_tab'),
    path('reset/<uidb64>/<token>/', CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('register/', views.register, name='register'),
    path('login/activate/<uidb64>/<token>/', views.activate, name='activate'),
]
    
