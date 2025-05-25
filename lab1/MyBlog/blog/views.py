import time
from django.shortcuts import render, get_object_or_404, redirect
from .models import Blog, UserProfile
from django.contrib.auth import authenticate, login, logout
from .forms import BlogForm, RegisterForm, LoginForm, OTPAuthForm
from django.views.generic import ListView, DetailView, UpdateView, DeleteView
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp import devices_for_user
import qrcode
from django.contrib import messages
from io import BytesIO
from base64 import b64encode

def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()
            login(request, user)
            refresh = RefreshToken.for_user(user)
            request.session['access_token'] = str(refresh.access_token)
            request.session['refresh_token'] = str(refresh)
            UserProfile.objects.create(user=user)
            return redirect('login')
    else:
        form = RegisterForm()
    return render(request, 'blog/register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                profile = UserProfile.objects.get(user=user)
                if profile.otp_enabled:
                    return render(request, 'blog/2fa-auth.html', {'user_id': user.id, 'form': OTPAuthForm()})
                refresh = RefreshToken.for_user(user)
                request.session['access_token'] = str(refresh.access_token)
                request.session['refresh_token'] = str(refresh)
                login(request,user)
                return redirect('main')
            else:
                messages.error(request, 'Неверное имя пользователя или пароль')
    else:
        form = LoginForm()
    return render(request, 'blog/login.html', {'form': form})

def generate_qr_code(device):
    qr = qrcode.make(device.config_url)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)
    return b64encode(buffer.getvalue()).decode('utf-8')

def setup_2fa(request):
    device, device_created = TOTPDevice.objects.get_or_create( # Time-based One-Time Password
        user=request.user,
        name='default',
        defaults={'confirmed': False}
    )
    profile, profile_created = UserProfile.objects.get_or_create(user=request.user)
    if request.method == 'POST':
        form = OTPAuthForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data['otp_code']
            if device.verify_token(token):
                device.confirmed = True
                device.save()
                profile.otp_enabled = True
                profile.save()
                messages.success(request, 'Двухфакторная аутентификация подключена. Перенаправление...')
                return redirect('main')
            else:
                messages.error(request, 'Неверный код')
                return render(request, 'blog/setup_2fa.html', {
                    'form': form,
                    'qr_code': generate_qr_code(device),
                })
    else:
        form = OTPAuthForm()
    qr_code = generate_qr_code(device)
    return render(request, 'blog/setup_2fa.html', {'form': form, 'qr_code': qr_code})

def disable_2fa(request):
    if request.method == 'POST':
        profile = UserProfile.objects.get(user=request.user)
        profile.otp_enabled = False
        profile.save()
        TOTPDevice.objects.filter(user=request.user).delete()
        messages.success(request, 'Двухфакторная аутентификация успешно отключена')
        return redirect('main')
    else:
        return render(request, 'blog/disable_2fa.html')

def verify_2fa(request):
    if request.method == 'POST':
        form = OTPAuthForm(request.POST)
        user_id = request.POST.get('user_id')
        if form.is_valid():
            otp_code = form.cleaned_data.get('otp_code')
            user = User.objects.get(id=user_id)
            devices = devices_for_user(user)
            if not any(device.verify_token(otp_code) for device in devices):
                messages.error(request, 'Неверный код')
            else:
                login(request,user)
                return redirect('main')
    else:
        form = OTPAuthForm()
        user_id = request.POST.get('user_id')
    return render(request, 'blog/2fa-auth.html', {'user_id': user_id, 'form': form})

def logout_view(request):
    if 'refresh_token' in request.session:
        try:
            refresh_token = request.session['refresh_token']
            token = RefreshToken(refresh_token)
            token.blacklist()
        except Exception as e:
            pass
    logout(request)
    request.session.flush()
    return redirect('main')

class UpdateBlog(UpdateView):
    model = Blog
    template_name = 'blog/blog-update.html'
    form_class = BlogForm

class DeleteBlog(DeleteView):
    model = Blog
    success_url = '/blogs/'
    template_name = 'blog/blog-delete.html'

def main(request):
    if request.user.is_authenticated:
        profile = UserProfile.objects.get(user=request.user)
        return render(request, 'blog/main.html', {'profile': profile})
    else:
        return render(request, 'blog/main.html')

class ShowBlogs(ListView):
    model = Blog
    template_name = 'blog/index.html'
    context_object_name = 'blogs'
    ordering = ['-created_at']

class ShowBlogInfo(DetailView):
    model = Blog
    template_name = 'blog/blog_info.html'
    context_object_name = 'blog'

def blog_create(request):
    permission_classes = [IsAuthenticated]

    if request.method == 'POST':
        form = BlogForm(request.POST)
        if form.is_valid():
            blog = form.save(commit=False) # без автоматического сохранения в бд
            blog.author = request.user
            blog.save()
            return redirect('blog-info', pk=blog.id)
    else:
        form = BlogForm()
    return render(request, 'blog/blog_form.html', {'form': form})