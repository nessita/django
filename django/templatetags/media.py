from django import template

register = template.Library()


@register.filter
def with_nonce(media, nonce):
    """
    Render a Media object with a CSP nonce applied to all script and link tags.

    Usage::

        {% load media %}
        {{ form.media|with_nonce:csp_nonce }}
    """
    return media.render(attrs={"nonce": nonce} if nonce else None)
