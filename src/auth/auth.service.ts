import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { compare, hash } from 'bcrypt';
import { Model } from 'mongoose';
import { LoginDto } from './dtos/login.dto';
import { SignupDto } from './dtos/signup.dto';
import { User } from './schemas/user.schema';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private UserModel: Model<User>,
    private readonly jwtService: JwtService,
  ) {}

  async signup(signupDate: SignupDto) {
    const { name, email, password } = signupDate;
    const emailIsUse = await this.UserModel.findOne({
      email: email,
    });
    if (emailIsUse) {
      throw new BadRequestException('Email is already in use');
    }
    const hashedPassword = await hash(password, 10);
    await this.UserModel.create({
      name,
      email,
      password: hashedPassword,
    });
    console.log(signupDate);
  }

  async login(credentials: LoginDto) {
    const { email, password } = credentials;
    const user = await this.UserModel.findOne({ email: email });
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const passwordMatch = await compare(password, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Invalid credentials');
    }
    return this.generateJwtToken(user.id);
  }

  private generateJwtToken(userId: string) {
    const accessToken = this.jwtService.sign({ userId });
    return { accessToken };
  }
}
