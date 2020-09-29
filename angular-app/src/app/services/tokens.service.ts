import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { map,tap } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class TokensService {

  constructor(private httpClient: HttpClient) { }

  token: string;

  getToken = () => {
    return this.httpClient.get('http://localhost:49288/api/token', { withCredentials: true })
      .pipe(
        tap((x: string) => {
          if (x) {
            this.token = x;
            console.log(this.token);
            localStorage.setItem('token', JSON.stringify(this.token));
          }
        })
      );
  }
}
