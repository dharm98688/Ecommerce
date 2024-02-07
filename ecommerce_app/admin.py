from django.contrib import admin
from ecommerce_app.models import Contact, Product, Orders, OrderUpdate
# Register your models here.


class ContactModelAdmin(admin.ModelAdmin):
    list_display = ("name", "email", "phone")


class ProductModelAdmin(admin.ModelAdmin):
    list_display = ("product_name",)


admin.site.register(Contact, ContactModelAdmin)
admin.site.register(Product, ProductModelAdmin)
admin.site.register(Orders)
admin.site.register(OrderUpdate)
