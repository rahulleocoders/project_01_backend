from django.db import models

class BaseContent(models.Model):
    created_on = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    class Meta:
      abstract = True