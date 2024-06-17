import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dtos/login.dto';
import { RefreshTokenDto } from './dtos/refresh-token.dto';
import { SignupDto } from './dtos/signup.dto';

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
}
