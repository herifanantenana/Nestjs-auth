import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { hash } from 'bcrypt';
import { Model } from 'mongoose';
import { SignupDto } from './dtos/signup.dto';
import { User } from './schemas/user.schema';

@Injectable()
export class AuthService {
  constructor(@InjectModel(User.name) private UserModel: Model<User>) {}

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
}
