from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from .utils import generate_token, TokenGenerator
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError
from django.core.mail import EmailMessage
from django.conf import settings
from django.views.generic import View
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.tokens import PasswordResetTokenGenerator


# Create your views here.


def signup(request):
    if request.method == 'POST':
        # fullname = request.POST['fullname']
        # username = request.POST['username']
        email = request.POST['email']
        # phone = request.POST['phone']
        password = request.POST['password']
        cpassword = request.POST['cpassword']

        if password != cpassword:
            # return HttpResponse("Password is not match")
            messages.warning(request, "Password is not matching")
            return render(request, 'signup.html')

        try:
            if User.objects.get(email=email):
                # return HttpResponse("Email is already exists!")
                messages.warning(request, 'email is already taken')
                return render(request, 'signup.html')
        except Exception as identifier:
            pass

        user = User.objects.create_user(email, email, password)
        user.is_active = False
        user.save()
        email_subject = "Activate Your account"
        message = render_to_string('activate.html', {
            'user': user,
            'domain': '127.0.0.1:8000',
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user)
        })

        email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
        email_message.send()
        messages.success(request, "Activate Your Account by clicking the link in your gmail")
        return redirect("authcart:login")

    return render(request, 'signup.html')


def handlelogin(request):
    if request.method == 'POST':

        username = request.POST['email']
        userpassword = request.POST['password']
        myuser = authenticate(username=username, password=userpassword)

        if myuser is not None:
            login(request, myuser)
            messages.success(request, "Login Success")
            return redirect("ecommerce_app:index")
            # return render(request, 'index.html')
        else:
            messages.error(request, "Invalid credentials")
            return redirect('authcart:login')

    return render(request, 'login.html')


def handlelogout(request):
    logout(request)
    messages.info(request, 'logout successfully!')
    return render(request, 'login.html')


class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as identifier:
            user = None
        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.info(request, "Account activated successfully")
            return redirect("authcart:login")
        return render(request, 'activatefail.html')


def contact(request):
    return render(request, 'contactus.html')


class RequestResetEmailView(View):
    def get(self, request):
        return render(request, 'request-reset-email.html')

    def post(self, request):
        email = request.POST['email']
        user = User.objects.filter(email=email)

        if user.exists():
            # current_site=get_current_site(request)
            email_subject = '[Reset Your Password]'
            message = render_to_string('reset-user-password.html', {
                'domain': '127.0.0.1:8000',
                'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token': PasswordResetTokenGenerator().make_token(user[0])
            })

            # email_message=EmailMessage(email_subject,message,settings.EMAIL_HOST_USER,[email])
            # email_message.send()

            messages.info(request,
                          f"WE HAVE SENT YOU AN EMAIL WITH INSTRUCTIONS ON HOW TO RESET THE PASSWORD {message} ")
            return render(request, 'request-reset-email.html')


class SetNewPasswordView(View):
    def get(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token
        }
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.warning(request, "Password Reset Link is Invalid")
                return render(request, 'request-reset-email.html')

        except DjangoUnicodeDecodeError as identifier:
            pass

        return render(request, 'set-new-password.html', context)

    def post(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token
        }
        password = request.POST['pass1']
        confirm_password = request.POST['pass2']
        if password != confirm_password:
            messages.warning(request, "Password is Not Matching")
            return render(request, 'set-new-password.html', context)

        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()
            messages.success(request, "Password Reset Success Please Login with NewPassword")
            return redirect('authcart:login')

        except DjangoUnicodeDecodeError as identifier:
            messages.error(request, "Something Went Wrong")
            return render(request, 'set-new-password.html', context)

        return render(request, 'set-new-password.html', context)
