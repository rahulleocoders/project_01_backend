# Generated by Django 4.0.6 on 2023-07-18 06:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_teaminvite_contact_teaminvite_country_code_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='otp',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='otp_expiry_date',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]