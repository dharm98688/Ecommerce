# Generated by Django 4.2.9 on 2024-02-05 13:43

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("ecommerce_app", "0002_product"),
    ]

    operations = [
        migrations.AlterField(
            model_name="product",
            name="image",
            field=models.ImageField(upload_to="media/images"),
        ),
    ]