from django.contrib.auth import logout
from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from incidents.services import record_login_attempt

from .serializers import LoginSerializer, serialize_user


class ApiLoginView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = [TokenAuthentication]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_login"

    def post(self, request):
        serializer = LoginSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        record_login_attempt(
            username=user.get_username(),
            user=user,
            successful=True,
            request=request,
        )
        token, _ = Token.objects.get_or_create(user=user)
        return Response(
            {"data": {"token": token.key, "user": serialize_user(user)}},
            status=status.HTTP_200_OK,
        )


class ApiLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if isinstance(request.successful_authenticator, TokenAuthentication):
            request.auth.delete()
        else:
            logout(request)
        return Response(status=status.HTTP_204_NO_CONTENT)


class ApiMeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"data": {"user": serialize_user(request.user)}})
