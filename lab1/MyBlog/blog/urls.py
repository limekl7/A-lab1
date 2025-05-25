from django.urls import path
from . import views

urlpatterns = [
    path('', views.main, name="main"),
    path('blogs/', views.ShowBlogs.as_view(), name='index'),
    path('blog_create/', views.blog_create, name='blog_create'),
    path('login/', views.login_view, name='login'),
    path('blogs/<int:pk>', views.ShowBlogInfo.as_view(), name='blog-info'),
    path('blogs/<int:pk>/update', views.UpdateBlog.as_view(), name='blog-update'),
    path('blogs/<int:pk>/delete', views.DeleteBlog.as_view(), name='blog-delete'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('login/2fa', views.verify_2fa, name='verify-2fa'),
    path('2fa_setup/', views.setup_2fa, name='2fa-setup'),
    path('disable_2fa/', views.disable_2fa, name='2fa-disable')
]