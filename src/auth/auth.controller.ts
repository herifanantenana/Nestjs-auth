import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dtos/signup.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  //TODO: Post Signup
  @Post('signup') //auth/signup
  async signUp(@Body() signupData: SignupDto): Promise<any> {
    // Call the service
    this.authService.signup(signupData);
  }

  //TODO: Post Login

  //TODO: Post Refresh Token
}
