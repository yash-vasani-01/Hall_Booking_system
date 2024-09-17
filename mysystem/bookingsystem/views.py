from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib import messages
from django.contrib.auth.models import User
from .models import data,admin_data,SeminarHall,BookingRequest
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.core.exceptions import ValidationError
from .validators import CustomPasswordValidator
from django.core.mail import send_mail
from django.conf import settings
from django.http import HttpResponse
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from datetime import datetime
from datetime import datetime, date


def welcome(request):
    return render(request,'welcome.html')
def home(request):
    alldata=data.objects.all()
    return render(request,'index1.html',{'alldata':alldata})
def login_(request):
    # Check if the user is already authenticated
    if request.user.is_authenticated:
        user_status = data.objects.filter(email=request.user.email).first()
        if user_status:
            if 1 in user_status.status and 2 in user_status.status:
                return redirect('role')
            # Redirect based on user status
            elif 1 in user_status.status:  # Assuming 1 is for Admin
                return redirect('admin_page')
            elif 2 in user_status.status:  # Assuming 2 is for Faculty
                return redirect('faculty_page')
        else:
            messages.error(request, "User status not found!")
            return redirect('welcome')  # Redirect to a safe page

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Authenticate using the provided username and password
        user = authenticate(request, username=username, password=password)

        if user is not None:
            user_status = data.objects.filter(email=user.email).first()
            if user_status:
                # Check if user has the required status
                if 1 in user_status.status and 2 in user_status.status:
                    login(request, user)
                    return redirect('role')  # Redirect to role selection if both statuses are present
                elif 1 in user_status.status :
                    login(request, user)
                    messages.success(request, "Successful log in")
                    return redirect('admin_page')  # Redirect to home if user has appropriate status
                elif 2 in user_status.status :
                    login(request, user)
                    messages.success(request, "Successful log in")
                    return redirect('faculty_page')  # Redirect to home if user has appropriate status
            else:
                messages.error(request, "User status not found!")
                return redirect('login')
        else:
            messages.error(request, "Log in failed! Check your credentials and try again.")
            return redirect('login')

    return render(request, 'index.html')

def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST['confirm_password']

        # Validate password using CustomPasswordValidator
        password_validator = CustomPasswordValidator()
        
        try:
            # Validate password rules
            password_validator.validate(password)
        except ValidationError as e:
            messages.error(request, e.messages[0])
            return redirect('register')

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('register')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return redirect('register')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email is already registered.")
            return redirect('register')

        # If all validations pass, create the user
        newuser = User.objects.create_user(username, email, password)
        newuser.save()
        messages.success(request, "Your account has been created successfully")
        return redirect('login')

    return render(request, 'register.html')

def logout_(request):
    logout(request)
    messages.success(request,'You are Logged Out success')
    return redirect('login')


def record(request,pk):
    user_data=data.objects.get(id=pk)
    return render(request,'record.html',{'user_data':user_data})

@login_required
def admin_page(request):
    user_data=data.objects.filter(email=request.user.email).first()
    if 1  not in user_data.status:
        messages.error(request, "Access denied. Admins only.")
        return redirect('login')
    return render(request,'admin_.html')

@login_required
def faculty_page(request):
    user_data=data.objects.filter(email=request.user.email).first()
    if 2  not in user_data.status:
        messages.error(request, "Access denied. Faculty only.")
        return redirect('login')
    return render(request,'faculty_.html')
def role(request):
    print("Accessing role view")  
    user_role=request.user
    user_role_data=data.objects.filter(email=user_role.email).first()
    
    if request.method=="POST":
        select_role=request.POST.get('role')
        print(f"Selected role: {select_role}")
        
        if select_role=="Admin" and 1 in user_role_data.status:
            return redirect('admin_page')
        elif select_role=="Faculty" and 2 in user_role_data.status:
            return redirect("faculty_page")    
    return render(request,'choose_role.html')



def add_seminar_hall(request):
    if request.method == 'POST':
        institute_name = request.POST.get('institute_name')
        hall_name = request.POST.get('hall_name')
        location = request.POST.get('location')
        capacity = request.POST.get('capacity')
        audio_system = request.POST.get('audio_system') == 'on'
        projector = request.POST.get('projector') == 'on'
        internet_wifi = request.POST.get('wifi') == 'on'

        # Check if the hall with the same name exists in the same institute
        if SeminarHall.objects.filter(institute_name=institute_name, hall_name=hall_name).exists():
            messages.error(request,"A seminar hall with this name already exists in the selected institute.")
            return redirect('add_hall')

        # If no duplicate found, create a new seminar hall
        SeminarHall.objects.create(
            institute_name=institute_name,
            hall_name=hall_name,
            location=location,
            capacity=capacity,
            audio_system=audio_system,
            projector=projector,
            internet_wifi=internet_wifi
        )
        
        messages.error(request,"Seminar hall details added successfully!")
        return redirect('add_hall')
    
    return render(request, 'add_hall.html')

def get_hall_details_by_name(request, hall_name, institute_name):
    halls = SeminarHall.objects.filter(hall_name=hall_name, institute_name=institute_name)
    if halls.exists():
        hall = halls.first()  
        data = {
            'location': hall.location,
            'capacity': hall.capacity,
            'projector': hall.projector,
            'audio': hall.audio_system,
            'wifi': hall.internet_wifi,
        }
        return JsonResponse(data)
    else:
        return JsonResponse({'error': 'Hall not found'}, status=404)
    
def institute_info(request, institute_name):
    halls = SeminarHall.objects.filter(institute_name=institute_name)
    return render(request, 'hall_information.html', {
        'institute_name': institute_name,
        'halls': halls,
    })
    
    
def book_hall(request, hall_name, institutename):
    if request.method == 'POST':
        date_str = request.POST.get('date')
        start_time = request.POST.get('start_time')
        end_time = request.POST.get('end_time')

        # Convert start_time and end_time to datetime.time objects
        try:
            booking_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            start_time = datetime.strptime(start_time, '%H:%M').time()
            end_time = datetime.strptime(end_time, '%H:%M').time()
        except ValueError:
            messages.error(request, 'Invalid time format. Please use HH:MM format.')
            return redirect('book_hall', hall_name=hall_name, institutename=institutename)
        
        today = date.today()  
        current_time = datetime.now().time()
        if booking_date == today and start_time <= current_time:
            messages.error(request, 'Start time must be in the future.')
            return redirect('book_hall', hall_name=hall_name, institutename=institutename)
        if end_time <= start_time:
            messages.error(request, 'End time must be after the start time.')
            return redirect('book_hall', hall_name=hall_name, institutename=institutename)

        try:
            # Fetch the specific hall for the selected institute
            hall = SeminarHall.objects.get(hall_name=hall_name, institute_name=institutename)
        except SeminarHall.DoesNotExist:
            messages.error(request, 'The selected hall does not exist in this institute.')
            return redirect('institute_info')

        try:
            # Fetch the admin responsible for the institute
            admin = admin_data.objects.get(institute_name=hall.institute_name)
        except admin_data.DoesNotExist:
            messages.error(request, 'Admin for this institute does not exist.')
            return redirect('faculty_page')

        # Fetch the current requester (faculty)
        requester = data.objects.get(username=request.user.username)

        # Check if the hall is already booked for the requested date and time
        existing_bookings = BookingRequest.objects.filter(
            institute_name=hall.institute_name,
            hall_name=hall.hall_name,
            date=date_str,
            status='pending'
        )

        # Check for overlapping time slots
        for booking in existing_bookings:
            existing_start = booking.start_time
            existing_end = booking.end_time

            if (start_time < existing_end and end_time > existing_start):
                messages.error(request, 'The hall is not available for the requested time slot.')
                return redirect('book_hall', hall_name=hall_name, institutename=institutename)

        # If no overlap, create a new booking request
        booking = BookingRequest(
            institute_name=hall.institute_name,
            hall_name=hall.hall_name,
            date=date_str,
            start_time=start_time,
            end_time=end_time,
            status='pending',
            requester_name=requester.username,
            admin=admin
        )
        booking.save()
        messages.success(request, 'Your booking request has been submitted!')
        return redirect('faculty_page')

    try:
        hall = SeminarHall.objects.get(hall_name=hall_name, institute_name=institutename)
    except SeminarHall.DoesNotExist:
        hall = None

    return render(request, 'book_hall.html', {'hall': hall})



def faculty_request_list(request):
    requests = BookingRequest.objects.filter(requester_name=request.user.username)

    return render(request, 'faculty_request.html', {
        'requests': requests
    })  
    
def cancel_request(request, request_id):
    try:
        booking_request = BookingRequest.objects.get(id=request_id, requester_name=request.user.username)
        booking_request.delete()  
        messages.success(request, 'Booking request cancelled.')
    except BookingRequest.DoesNotExist:
        messages.error(request, 'Booking request not found.')

    return redirect('faculty_request')



def admin_request_list(request):
    user_data = data.objects.filter(email=request.user.email).first()
    if 1 not in user_data.status:
        messages.error(request, "Access denied. Admins only.")
        return redirect('login')

    try:
        admin_instance = admin_data.objects.get(username=request.user.username)
        print(request.user.username)
    except admin_data.DoesNotExist:
        return redirect('login')

    # Get all booking requests for the admin's institute
    requests = BookingRequest.objects.filter(institute_name=admin_instance.institute_name)

    if request.method == 'POST':
        booking_id = request.POST.get('booking_id')
        action = request.POST.get('action')
        booking_request = BookingRequest.objects.get(id=booking_id)
        
        
        try:
            requester_data = data.objects.get(username=booking_request.requester_name)
            requester_email = requester_data.email  
        except data.DoesNotExist:
            
            return HttpResponse("Requester not found in the system")

        if action == 'accept':
            booking_request.status = 'accepted'
           
        elif action == 'reject':
            booking_request.status = 'rejected'  
           
        booking_request.save()
        send_notification_email(
            requester_email,
            booking_request.requester_name,
            booking_request.hall_name,
            booking_request.institute_name,
            action,
            booking_request.date,
            booking_request.start_time,
            booking_request.end_time
            
        )

    requests = BookingRequest.objects.filter(institute_name=admin_instance.institute_name, status='pending')


    context = {
        'requests': requests
    }
    return render(request, 'admin_.html', context)


def send_notification_email(requester_email, requester_name, hall_name,institute_name, action,date,start_time,end_time):
    subject = f"Booking Request {action.capitalize()}"
    
    
    admin_instance = admin_data.objects.get(institute_name=institute_name)

    html_code=render_to_string('book_email.html', {
        'requester_name': requester_name,
        'hall_name': hall_name,
        'institute_name': institute_name,
        'action': action,
        'date': date,
        'start_time': start_time,
        'end_time': end_time, 
        'admin_email':admin_instance.email,
        'university_name': 'Charusat University'  
    })
    
    text = strip_tags(html_code)
    
    email = EmailMultiAlternatives(
        subject,
        text,
        admin_instance.email,  
        [requester_email]  
    )
    email.attach_alternative(html_code, "text/html")
    email.send()
    
