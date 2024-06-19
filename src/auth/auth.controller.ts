import { Body, Controller, Post, Put, Req, UseGuards } from '@nestjs/common';
import { AuthGuard } from 'src/guards/auth.guard';
import { AuthService } from './auth.service';
import { ChangePasswordDto } from './dtos/change-password.dto';
import { LoginDto } from './dtos/login.dto';
import { RefreshTokenDto } from './dtos/refresh-token.dto';
import { SignupDto } from './dtos/signup.dto';
import { ForgotPasswordDto } from './dtos/forgot-password.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  //TODO: Post Signup
  @Post('signup') //auth/signup
  async signUp(@Body() signupData: SignupDto): Promise<any> {
    // Call the service
    return this.authService.signup(signupData);
  }

  //TODO: Post Login
  @Post('login') //auth/login
  async login(@Body() credential: LoginDto): Promise<any> {
    // Call the service
    return this.authService.login(credential);
  }

  //TODO: Post Refresh Token
  @Post('refresh') //auth/refresh
  async refreshToken(@Body() refreshToken: RefreshTokenDto): Promise<any> {
    // Call the service
    return this.authService.refreshToken(refreshToken);
  }

  //TODO: Post Change Password
  @UseGuards(AuthGuard)
  @Put('change-password') //auth/change-password
  async changePassword(
    @Req() { userId },
    @Body() changePasswordData: ChangePasswordDto,
  ): Promise<any> {
    // Call the service
    return this.authService.changePassword(
      userId,
      changePasswordData.oldPassword,
      changePasswordData.newPassword,
    );
  }

  //TODO: Forgot Password
  @Post('forgot-password') //auth/forgot-password
  async forgotPassword(
    @Body() forgotPasswordData: ForgotPasswordDto,
  ): Promise<any> {
    // Call the service
    return this.authService.forgotPassword(forgotPasswordData.email);
  }

  //TODO: Reset Password
}
