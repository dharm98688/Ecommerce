# Generated by Django 4.2.9 on 2024-02-07 13:09

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("ecommerce_app", "0009_alter_orderupdate_order_id"),
    ]

    operations = [
        migrations.AlterField(
            model_name="orderupdate",
            name="order_id",
            field=models.IntegerField(default=""),
        ),
    ]
