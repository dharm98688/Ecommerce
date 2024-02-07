from django.urls import path, include
from . import views

app_name = 'ecommerce_app'

urlpatterns = [
    path("", views.index, name='index'),
    path("contact/", views.contactus, name='contactus'),
    path("about/", views.about, name='about'),
    path("checkout/", views.checkout, name = 'checkout'),
    path("handlerequest/", views.handlerequest, name='handlerequest'),
    path("profile", views.profile, name='profile')
]