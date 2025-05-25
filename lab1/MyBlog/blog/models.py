from django.db import models
from django.contrib.auth.models import User
from django_otp.plugins.otp_totp.models import TOTPDevice

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp_enabled = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username


class Blog(models.Model):
    title = models.CharField('Название', max_length=150, unique=True)
    content = models.TextField('Текст блога')
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='articles')
    created_at = models.DateTimeField('Дата создания', auto_now_add=True)
    updated_at = models.DateTimeField('Дата редактирования', auto_now=True)

    def get_absolute_url(self):
        return f'/blogs/{self.id}'

    def __str__(self):
        return self.title