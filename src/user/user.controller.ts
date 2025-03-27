import { Body, Controller, Param, Patch, Post, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { ChangePasswordDto, CreateUserDto, LoginDto, RefreshTokenDto } from './dto/user.dto';
import { AuthGuard } from '@nestjs/passport';

@Controller('user')
export class UserController {
    constructor(private readonly userService: UserService){}
    
    @Post('register')
    async register(@Body() createUserDto: CreateUserDto) {
      return this.userService.create(createUserDto);
    }
  
    @Post('login')
    async login(@Body() loginDto: LoginDto) {
      return this.userService.login(loginDto);
    }
  
    @Post('refreshToken')
    async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
      return this.userService.refreshToken(refreshTokenDto.refreshToken);
    }
  
    @Post('verify/:id')
    async verifyUser(@Param('id') id: string, @Body('verificationCode') verificationCode: string) {
      return this.userService.verifyUser(id, verificationCode);
    }
  
    @UseGuards(AuthGuard('jwt'))
    @Patch('changePassword/:id')
    async changePassword(@Param('id') id: string, @Body() changePasswordDto: ChangePasswordDto) {
      return this.userService.changePassword(id, changePasswordDto);
    }
  
}


  
   
   