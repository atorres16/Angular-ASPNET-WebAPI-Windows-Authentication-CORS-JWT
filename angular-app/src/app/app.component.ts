import { TokensService } from './services/tokens.service';
import { ItemsService } from './services/items.service';
import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {
  constructor(private itemsService: ItemsService, private tokenService: TokensService) { }
  value: any;

  ngOnInit(): void {
    this.tokenService.getToken()
      .subscribe((t) => {
        console.log(t);

        this.itemsService.getItems()
          .subscribe((its) => {
            console.log(its);
            this.value = its;
          },
            (err) => console.error(err)
          );
      });
  }
}
