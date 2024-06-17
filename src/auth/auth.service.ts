import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { compare, hash } from 'bcrypt';
import { Model, ObjectId } from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
import { LoginDto } from './dtos/login.dto';
import { RefreshTokenDto } from './dtos/refresh-token.dto';
import { SignupDto } from './dtos/signup.dto';
import { RefreshToken } from './schemas/refresh-token.schema';
import { User } from './schemas/user.schema';
@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private UserModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private RefreshTokenModel: Model<RefreshToken>,
    private readonly jwtService: JwtService,
  ) {}

  async signup(signupDate: SignupDto) {
    const { name, email, password } = signupDate;
    const emailIsUse = await this.UserModel.findOne({
      email: email,
    }).exec();
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
    const user = await this.UserModel.findOne({ email: email }).exec();
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const passwordMatch = await compare(password, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Invalid credentials');
    }
    return this.generateJwtToken(user.id);
  }

  async refreshToken(refreshToken: RefreshTokenDto) {
    const token = await this.RefreshTokenModel.findOne({
      token: refreshToken.token,
      expires: { $gt: new Date() },
    }).exec();
    if (!token) {
      throw new UnauthorizedException('Invalid token');
    }
    return this.generateJwtToken(token.userId);
  }

  private async generateJwtToken(userId: string | ObjectId) {
    const accessToken = this.jwtService.sign({ userId });
    const refreshToken = uuidv4();
    await this.generateRefreshToken(refreshToken, userId);
    return { accessToken, refreshToken, userId };
  }

  private async generateRefreshToken(token: string, userId: string | ObjectId) {
    const expires = new Date();
    expires.setDate(expires.getDate() + 5);
    return this.RefreshTokenModel.updateOne(
      { userId },
      { token, expires },
      { upsert: true },
    );
  }
}
