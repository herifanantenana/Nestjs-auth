import { BadRequestException, Injectable } from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import { User } from './schemas/user.schema';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

@Injectable()
export class AuthService {
  constructor(@InjectModel(User.name) private UserModel: Model<User>) {}

  async signup(signupDate: SignupDto) {
    const emailIsUse = await this.UserModel.findOne({
      email: signupDate.email,
    });
    if (emailIsUse) {
      throw new BadRequestException('Email is already in use');
    }
    console.log(signupDate);
  }
}
