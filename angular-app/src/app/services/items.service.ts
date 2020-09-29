import { TokensService } from './tokens.service';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class ItemsService {

  constructor(private httpClient: HttpClient, private tokenService: TokensService) { }

  httpOptions = {
    headers: new HttpHeaders({})
  };


  getItems = () => {
    if (this.tokenService.token) {
      this.httpOptions.headers = this.httpOptions.headers.set('Authorization', 'Bearer ' + this.tokenService.token);
    }
    return this.httpClient.get('http://localhost:49288/api/items', this.httpOptions);
  }
}
